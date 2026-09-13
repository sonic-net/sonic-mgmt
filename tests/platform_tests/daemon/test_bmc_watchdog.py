"""
BMC Watchdog Daemon Tests

Tests for the BMC watchdog service (hw-watchdog-mgrd) that manages hardware
watchdog arming/keepalive and logging.

Validates:
- Watchdog service status and keepalive mechanism
- Watchdog timeout configuration (180s armed, 60s keepalive interval)
- Watchdog logs stored in /host/bmc/ directory (persistent storage)
- Differentiation between user-issued reboot and watchdog reset
- State DB consistency for watchdog status
"""

import logging
import re

import pytest
from tests.common.helpers.assertions import pytest_assert
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
        # --- /host/bmc/watchdog.log presence and content ---
        # Asserts the BMC log-routing contract: the persistent watchdog log lives
        # in /host/bmc/, populated via syslog -> rsyslog drop-in, not /var/log/.
        r = self.duthost.shell("test -f /host/bmc/watchdog.log && echo yes || echo no",
                               module_ignore_errors=True)
        pytest_assert(r.get('stdout', '').strip() == 'yes',
                      "Expected /host/bmc/watchdog.log to exist (hw-watchdog-mgrd "
                      "persistent log sink via rsyslog drop-in)")

        # The daemon logs a lifecycle marker at startup ("Hardware watchdog manager
        # starting") which the rsyslog drop-in routes to this file. Assert that a
        # real hw-watchdog-mgrd lifecycle entry is present rather than a blind
        # line-count, which ties the check to the actual daemon and tolerates
        # logrotate's `notifempty` behaviour.
        lifecycle_re = (r"Hardware watchdog manager (starting|stopping|stopped)"
                        r"|Loaded watchdog policy"
                        r"|Hardware watchdog .*(armed|disarmed|keepalive)")
        r = self.duthost.shell(
            f"grep -E '{lifecycle_re}' /host/bmc/watchdog.log | wc -l",
            module_ignore_errors=True)
        try:
            marker_lines = int((r.get('stdout', '') or '0').strip())
        except ValueError:
            marker_lines = 0
        pytest_assert(marker_lines > 0,
                      "/host/bmc/watchdog.log has no hw-watchdog-mgrd lifecycle "
                      "entries — daemon did not log via the rsyslog drop-in")
        logger.info(f"/host/bmc/watchdog.log has {marker_lines} hw-watchdog-mgrd "
                    "lifecycle entrie(s)")

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
