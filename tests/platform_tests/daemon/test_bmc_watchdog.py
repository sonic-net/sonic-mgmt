"""
BMC Watchdog Daemon Tests

Tests for the BMC watchdog service (hw-watchdog-mgrd) that manages hardware
watchdog arming/keepalive and logging.

Validates:
- Watchdog service status and keepalive mechanism
- Watchdog timeout configuration (180s armed, 60s keepalive interval)
- Watchdog logs stored in /host/bmc/ directory (persistent storage)
- Differentiation between user-issued reboot and watchdog reset
"""

import logging
import re

import pytest
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.bmc_utils import (
    get_host_boot_id,
    get_host_uptime,
    get_switch_host_or_skip_test,
)
from tests.common.reboot import wait_for_shutdown, wait_for_startup
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('bmc')
]


@pytest.fixture(scope="class")
def skip_if_no_watchdog(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Skip watchdog tests if watchdog is not supported on this platform.

    Detects:
    - watchdogutil command availability
    - Hardware watchdog support
    - BMC system detection
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.shell("which watchdogutil", module_ignore_errors=True)
    if result['rc'] != 0:
        logger.info("watchdogutil not available - skipping watchdog tests")
        pytest.skip("watchdogutil not found on this platform")

    result = duthost.shell("test -d /host/bmc && echo 'bmc' || echo 'no-bmc'",
                           module_ignore_errors=True)
    if 'no-bmc' in result['stdout']:
        logger.info("BMC not detected - some watchdog tests will be limited")

    return duthost


class TestBmcWatchdog:
    """BMC Watchdog functionality tests"""

    @pytest.fixture(autouse=True)
    def setup_class(self, skip_if_no_watchdog):
        """Setup for each test"""
        self.duthost = skip_if_no_watchdog

    def expect(self, condition, message):
        """Helper for soft assertions"""
        pytest_assert(condition, message)

    def test_watchdog_bmc_integration(self):
        """
        Verify BMC watchdog: arm/disarm via `watchdogutil` round-trips correctly
        AND `/host/bmc/watchdog.log` is the persistent log sink for the Aspeed
        `hw-watchdog-mgrd` daemon.

        The hw-watchdog-mgrd daemon:
          - Is the sole owner of /dev/watchdog0 and sends keepalives every 60s
            while armed — so this test is safe to run on a live BMC.
          - Arms at boot per platform policy (boot_arm/shutdown_protect in
            platform.json) rather than a fixed `watchdogutil arm -s 180`.
          - Emits lifecycle log lines via syslog (ident 'hw-watchdog-mgrd').
            An rsyslog drop-in (10-hw-watchdog-mgrd.conf) routes those messages
            to /host/bmc/watchdog.log (persistent eMMC) and stops them from
            reaching tmpfs /var/log.

        Pre-test arm state is restored in `finally`.
        """
        # --- /host/bmc/watchdog.log presence ---
        # Asserts the BMC log-routing contract: the persistent watchdog log lives
        # in /host/bmc/, populated via syslog -> rsyslog drop-in, not /var/log/.
        # Fresh-content routing is verified later, anchored to the arm/disarm round-trip.
        r = self.duthost.shell("test -f /host/bmc/watchdog.log && echo yes || echo no",
                               module_ignore_errors=True)
        pytest_assert(r.get('stdout', '').strip() == 'yes',
                      "Expected /host/bmc/watchdog.log to exist (hw-watchdog-mgrd "
                      "persistent log sink via rsyslog drop-in)")

        # Record the current size of the persistent log so the routing check below
        # inspects ONLY the bytes this test appends. Counting pre-existing lifecycle
        # lines is unsafe: rotated/stale entries from prior boots would mask a
        # currently broken daemon, and the DUT wall clock could be unreliable if the
        # RTC was stale at boot and was later stepped by NTP, so it's better not to
        # trust timestamp-based recency. A byte offset is monotonic regardless of
        # clock steps or rotation.
        r = self.duthost.shell("wc -c < /host/bmc/watchdog.log",
                               module_ignore_errors=True)
        try:
            log_offset = int((r.get('stdout', '') or '0').strip())
        except ValueError:
            log_offset = 0
        logger.info(f"/host/bmc/watchdog.log baseline size: {log_offset} bytes")

        # Negative: /var/log/watchdog* must NOT exist — that location violates
        # the BMC persistent-log convention.
        r = self.duthost.shell("ls /var/log/watchdog* 2>/dev/null | wc -l",
                               module_ignore_errors=True)
        stray = int((r.get('stdout', '') or '0').strip())
        pytest_assert(stray == 0,
                      f"Found {stray} watchdog log file(s) in /var/log — "
                      "BMC convention requires persistent logs in /host/bmc/")

        # --- Arm/Disarm transitions ---
        initial_state, initial_remaining = self._read_watchdog_status()
        pytest_assert(initial_state in ('Armed', 'Unarmed'),
                      f"Unexpected initial watchdog state: {initial_state!r}")
        logger.info(f"Initial watchdog state: {initial_state} (remaining={initial_remaining})")

        try:
            # If we start Unarmed, arm first so the disarm below is meaningful
            if initial_state == 'Unarmed':
                r = self.duthost.shell("watchdogutil arm -s 180", module_ignore_errors=True)
                pytest_assert(r['rc'] == 0,
                              f"watchdogutil arm failed: rc={r['rc']} stderr={r['stderr']!r}")
                pytest_assert(
                    wait_until(15, 2, 0, lambda: self._read_watchdog_status()[0] == 'Armed'),
                    "watchdogutil status did not report Armed after `watchdogutil arm -s 180`"
                )

            # Transition 1: Armed → Unarmed
            r = self.duthost.shell("watchdogutil disarm", module_ignore_errors=True)
            pytest_assert(r['rc'] == 0,
                          f"watchdogutil disarm failed: rc={r['rc']} stderr={r['stderr']!r}")
            pytest_assert(
                wait_until(15, 2, 0, lambda: self._read_watchdog_status()[0] == 'Unarmed'),
                "watchdogutil status did not report Unarmed after `watchdogutil disarm`"
            )
            logger.info("Disarm transition confirmed: status reports Unarmed")

            # Transition 2: Unarmed → Armed
            r = self.duthost.shell("watchdogutil arm -s 180", module_ignore_errors=True)
            pytest_assert(r['rc'] == 0,
                          f"watchdogutil arm failed: rc={r['rc']} stderr={r['stderr']!r}")
            pytest_assert(
                wait_until(15, 2, 0, lambda: self._read_watchdog_status()[0] == 'Armed'),
                "watchdogutil status did not report Armed after `watchdogutil arm -s 180`"
            )

            # --- Persistent-log routing contract (recency-anchored) ---
            # The disarm/arm round-trip above makes hw-watchdog-mgrd emit fresh
            # transition lines. Confirm they land in /host/bmc/watchdog.log by
            # scanning ONLY the bytes appended since log_offset — this proves the
            # daemon -> syslog -> rsyslog drop-in -> persistent eMMC path works
            # right now and cannot match stale entries from an earlier run/boot.
            marker_re = r"Hardware watchdog .*armed"

            def _appended_markers():
                res = self.duthost.shell(
                    f"tail -c +{log_offset + 1} /host/bmc/watchdog.log | "
                    f"grep -E '{marker_re}' | wc -l",
                    module_ignore_errors=True)
                try:
                    return int((res.get('stdout', '') or '0').strip())
                except ValueError:
                    return 0

            pytest_assert(
                wait_until(15, 2, 0, lambda: _appended_markers() > 0),
                "No fresh hw-watchdog-mgrd arm/disarm entries appeared in "
                "/host/bmc/watchdog.log after the watchdogutil round-trip — the "
                "daemon -> rsyslog drop-in -> persistent-log path is not working")
            logger.info("Fresh hw-watchdog-mgrd transition entrie(s) confirmed in "
                        "/host/bmc/watchdog.log after arm/disarm round-trip")

            state, remaining = self._read_watchdog_status()
            # Validate timeout when armed
            if state == 'Armed':
                if remaining is not None:
                    logger.info(f"Watchdog remaining time: {remaining}s (target: 180s)")
                    pytest_assert(remaining <= 180,
                                  f"Remaining time {remaining}s exceeds 180s timeout")
                    pytest_assert(remaining >= 30,
                                  f"Remaining time {remaining}s below minimum 30s")
                else:
                    logger.warning("Could not parse remaining time from watchdogutil output")
            else:
                logger.warning("Watchdog not armed - cannot verify timeout configuration")

        finally:
            current_state, _ = self._read_watchdog_status()
            if initial_state == 'Unarmed' and current_state != 'Unarmed':
                self.duthost.shell("watchdogutil disarm", module_ignore_errors=True)
            elif initial_state == 'Armed' and current_state != 'Armed':
                self.duthost.shell("watchdogutil arm -s 180", module_ignore_errors=True)

    def _read_watchdog_status(self):
        """Return (state, remaining) where state is 'Armed'|'Unarmed'|'' and remaining is int|None."""
        result = self.duthost.shell("watchdogutil status", module_ignore_errors=True)
        pytest_assert(result['rc'] == 0,
                      f"watchdogutil status failed: rc={result['rc']} stderr={result['stderr']!r}")
        out = result['stdout']
        state = ''
        if 'Armed' in out:
            state = 'Armed'
        elif 'Unarmed' in out:
            state = 'Unarmed'
        remaining = None
        m = re.search(r"Time remaining:\s*(\d+)\s*seconds", out)
        if m:
            remaining = int(m.group(1))
        return state, remaining

    @pytest.mark.disable_loganalyzer
    def test_watchdog_resets_bmc_switch_host_unaffected(self, localhost):
        """
        Verify the hardware watchdog resets the BMC when hw-watchdog-mgrd stops
        petting /dev/watchdog0, and that the paired Switch-Host is unaffected.

        Freezing the daemon with SIGSTOP stops the keepalives it sends to the
        watchdog (it is the sole owner of the device), so the SoC resets once the
        timeout expires. The watchdog is armed with the minimum 30s timeout first
        so the reset is bounded to ~15-30s instead of the 180s boot default.

        A BMC reset must not disturb the Switch-Host, so the Switch-Host boot_id
        and uptime must be unchanged after the BMC comes back.
        """
        duthost = self.duthost

        # Require a reachable paired Switch-Host so we can prove it is unaffected.
        switch_host = get_switch_host_or_skip_test(duthost)
        host_boot_id_before = get_host_boot_id(switch_host)
        host_uptime_before = get_host_uptime(switch_host)
        pytest_assert(host_boot_id_before,
                      "Could not read Switch-Host boot_id before the BMC reset")

        bmc_boot_id_before = get_host_boot_id(duthost)
        pytest_assert(bmc_boot_id_before,
                      "Could not read BMC boot_id before the reset")

        reset_triggered = False
        try:
            # Arm with the minimum timeout so the reset (once keepalives stop)
            # happens quickly and deterministically.
            r = duthost.shell("watchdogutil arm -s 30", module_ignore_errors=True)
            pytest_assert(r['rc'] == 0,
                          f"watchdogutil arm -s 30 failed: rc={r['rc']} stderr={r['stderr']!r}")
            pytest_assert(
                wait_until(15, 2, 0, lambda: self._read_watchdog_status()[0] == 'Armed'),
                "watchdogutil status did not report Armed after `watchdogutil arm -s 30`")

            # Freeze the daemon so it stops petting /dev/watchdog0. The hardware
            # watchdog will now expire and reset the BMC SoC.
            reset_triggered = True
            duthost.shell("systemctl kill -s SIGSTOP hw-watchdog-mgrd.service",
                          module_ignore_errors=True)

            # The reset drops the BMC mgmt channel; wait for SSH to go away then
            # come back. A 30s hw timeout means SSH should drop within ~30s.
            wait_for_shutdown(duthost, localhost, delay=10, timeout=90)
            reset_triggered = False  # reset happened; daemon restarts fresh on boot
            wait_for_startup(duthost, localhost, delay=10, timeout=300)
        finally:
            # If the watchdog did not reset the box (e.g. no real HW watchdog in
            # this environment), unfreeze and restart the daemon so it is left
            # healthy. After a real reset the daemon starts fresh on boot and
            # re-arms per the platform boot_arm policy.
            if reset_triggered:
                duthost.shell("systemctl kill -s SIGCONT hw-watchdog-mgrd.service",
                              module_ignore_errors=True)
                duthost.shell("systemctl restart hw-watchdog-mgrd.service",
                              module_ignore_errors=True)

        # --- Assert the BMC actually reset ---
        bmc_boot_id_after = get_host_boot_id(duthost)
        pytest_assert(bmc_boot_id_after,
                      "Could not read BMC boot_id after the reset")
        pytest_assert(bmc_boot_id_after != bmc_boot_id_before,
                      "BMC boot_id did not change — the watchdog did not reset the BMC "
                      f"(before={bmc_boot_id_before!r} after={bmc_boot_id_after!r})")
        logger.info("BMC reset confirmed: boot_id changed after watchdog expiry")

        # Soft observability only: reboot-cause string is platform-specific.
        cause = duthost.shell("show reboot-cause",
                              module_ignore_errors=True).get('stdout', '').strip()
        logger.info(f"BMC reboot-cause after watchdog reset: {cause!r}")

        # --- Assert the paired Switch-Host was unaffected ---
        host_boot_id_after = get_host_boot_id(switch_host)
        host_uptime_after = get_host_uptime(switch_host)
        pytest_assert(host_boot_id_after == host_boot_id_before,
                      "Switch-Host boot_id changed across the BMC reset — the BMC reset "
                      f"disturbed the Switch-Host (before={host_boot_id_before!r} "
                      f"after={host_boot_id_after!r})")
        pytest_assert(host_uptime_after == host_uptime_before,
                      "Switch-Host uptime changed across the BMC reset — the BMC reset "
                      f"disturbed the Switch-Host (before={host_uptime_before!r} "
                      f"after={host_uptime_after!r})")
        logger.info("Switch-Host unaffected by BMC reset: boot_id and uptime unchanged")

    def _restart_daemon_and_wait_active(self):
        """Restart hw-watchdog-mgrd and wait until systemd reports it active."""
        r = self.duthost.shell("systemctl restart hw-watchdog-mgrd.service",
                               module_ignore_errors=True)
        pytest_assert(r['rc'] == 0,
                      f"Failed to restart hw-watchdog-mgrd.service: "
                      f"rc={r['rc']} stderr={r['stderr']!r}")
        pytest_assert(
            wait_until(30, 2, 0, lambda: self.duthost.shell(
                "systemctl is-active hw-watchdog-mgrd.service",
                module_ignore_errors=True).get('stdout', '').strip() == 'active'),
            "hw-watchdog-mgrd.service did not become active after restart")

    def _restore_arm_state(self, initial_state):
        """Return the watchdog to the arm state it was in before the test."""
        current_state, _ = self._read_watchdog_status()
        if initial_state == 'Armed' and current_state != 'Armed':
            self.duthost.shell("watchdogutil arm -s 180", module_ignore_errors=True)
        elif initial_state == 'Unarmed' and current_state != 'Unarmed':
            self.duthost.shell("watchdogutil disarm", module_ignore_errors=True)

    def test_daemon_restart_preserves_armed_state(self):
        """
        Verify restarting hw-watchdog-mgrd does not reset the BMC and restores
        the armed intent.

        A normal `systemctl restart` is not a system shutdown, so cleanup() takes
        the magic-close ('V') path and the hardware watchdog is cleanly disarmed
        for the restart gap — the BMC must NOT reset. On startup the daemon reads
        the armed intent from the tmpfs intent file and re-arms with the same
        timeout, so the watchdog is Armed again afterwards.

        Pre-test arm state is restored in `finally`.
        """
        duthost = self.duthost

        initial_state, _ = self._read_watchdog_status()
        bmc_boot_id_before = get_host_boot_id(duthost)
        pytest_assert(bmc_boot_id_before,
                      "Could not read BMC boot_id before the daemon restart")

        armed_timeout = 120
        try:
            # Arm with a known timeout so we can confirm the intent (and its
            # timeout) is restored across the restart.
            r = duthost.shell(f"watchdogutil arm -s {armed_timeout}", module_ignore_errors=True)
            pytest_assert(r['rc'] == 0,
                          f"watchdogutil arm -s {armed_timeout} failed: "
                          f"rc={r['rc']} stderr={r['stderr']!r}")
            pytest_assert(
                wait_until(15, 2, 0, lambda: self._read_watchdog_status()[0] == 'Armed'),
                f"watchdogutil status did not report Armed after "
                f"`watchdogutil arm -s {armed_timeout}`")

            self._restart_daemon_and_wait_active()

            # The BMC must not have reset across the restart.
            bmc_boot_id_after = get_host_boot_id(duthost)
            pytest_assert(bmc_boot_id_after == bmc_boot_id_before,
                          "BMC boot_id changed across a daemon restart — the restart "
                          f"reset the BMC (before={bmc_boot_id_before!r} "
                          f"after={bmc_boot_id_after!r})")

            # The armed intent (and its timeout) must be restored.
            pytest_assert(
                wait_until(15, 2, 0, lambda: self._read_watchdog_status()[0] == 'Armed'),
                "Watchdog is not Armed after daemon restart — armed intent was not restored")
            _, remaining = self._read_watchdog_status()
            if remaining is not None:
                pytest_assert(remaining <= armed_timeout,
                              f"Restored remaining time {remaining}s exceeds armed "
                              f"timeout {armed_timeout}s")
                pytest_assert(remaining >= 30,
                              f"Restored remaining time {remaining}s below minimum 30s")
            logger.info("Daemon restart preserved armed state; BMC did not reset")
        finally:
            self._restore_arm_state(initial_state)

    def test_daemon_restart_preserves_disarmed_state(self):
        """
        Verify a disarm intent survives a daemon restart.

        After `watchdogutil disarm`, restarting hw-watchdog-mgrd must leave the
        watchdog Unarmed: the tmpfs intent file records the disarm and
        _startup_arm() honours it, so the boot_arm platform policy does not
        silently re-arm the watchdog. The BMC must not reset either.

        Pre-test arm state is restored in `finally`.
        """
        duthost = self.duthost

        initial_state, _ = self._read_watchdog_status()
        bmc_boot_id_before = get_host_boot_id(duthost)
        pytest_assert(bmc_boot_id_before,
                      "Could not read BMC boot_id before the daemon restart")

        try:
            r = duthost.shell("watchdogutil disarm", module_ignore_errors=True)
            pytest_assert(r['rc'] == 0,
                          f"watchdogutil disarm failed: rc={r['rc']} stderr={r['stderr']!r}")
            pytest_assert(
                wait_until(15, 2, 0, lambda: self._read_watchdog_status()[0] == 'Unarmed'),
                "watchdogutil status did not report Unarmed after `watchdogutil disarm`")

            self._restart_daemon_and_wait_active()

            # The BMC must not have reset across the restart.
            bmc_boot_id_after = get_host_boot_id(duthost)
            pytest_assert(bmc_boot_id_after == bmc_boot_id_before,
                          "BMC boot_id changed across a daemon restart — the restart "
                          f"reset the BMC (before={bmc_boot_id_before!r} "
                          f"after={bmc_boot_id_after!r})")

            # The disarm intent must be honoured; boot policy must not re-arm.
            state_after, _ = self._read_watchdog_status()
            pytest_assert(state_after == 'Unarmed',
                          "Watchdog is not Unarmed after daemon restart — the disarm "
                          f"intent was not honoured (state={state_after!r})")
            logger.info("Daemon restart honoured disarm intent; BMC did not reset")
        finally:
            self._restore_arm_state(initial_state)
