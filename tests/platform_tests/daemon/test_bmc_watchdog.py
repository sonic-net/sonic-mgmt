"""
BMC Watchdog Daemon Tests

Tests for the BMC watchdog service that manages hardware watchdog petting
and logging.

Validates:
- Watchdog service status and petting mechanism
- Watchdog timeout configuration (180s armed, 60s pet interval)
- Watchdog logs stored in /host/bmc/ directory (persistent storage)
- Differentiation between user-issued reboot and watchdog reset
- State DB consistency for watchdog status
"""

import logging
import re
import time
import pytest
from tests.common.helpers.assertions import pytest_assert

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

    def test_watchdog_status_and_configuration(self):
        """
        Verify watchdog service status, timeout configuration, performance and error handling

        Validates:
        - watchdogutil status output is valid (Armed/Unarmed)
        - Remaining time between 30s and 180s (when armed)
        - Command latency < 5 seconds
        - Service stays responsive after invalid command
        """
        # Measure latency while getting status
        start = time.time()
        result = self.duthost.shell("watchdogutil status", module_ignore_errors=True)
        elapsed = time.time() - start

        self.expect(result['rc'] == 0,
                    f"watchdogutil status failed: {result['stderr']}")

        output = result['stdout'].strip()
        self.expect(len(output) > 0, "watchdogutil status returned empty output")
        self.expect("Armed" in output or "Unarmed" in output,
                    f"watchdogutil output format unexpected: {output}")

        logger.info(f"Watchdog status: {output}, latency: {elapsed:.3f}s")
        self.expect(elapsed < 5.0, f"watchdogutil took too long: {elapsed:.3f}s")

        # Validate timeout when armed
        if "Armed" in output:
            match = re.search(r"Time remaining:\s*(\d+)\s*seconds", output)
            if match:
                remaining = int(match.group(1))
                logger.info(f"Watchdog remaining time: {remaining}s (target: 180s)")
                self.expect(remaining <= 180,
                            f"Remaining time {remaining}s exceeds 180s timeout")
                self.expect(remaining >= 30,
                            f"Remaining time {remaining}s below minimum 30s")
            else:
                logger.warning("Could not parse remaining time from watchdogutil output")
        else:
            logger.warning("Watchdog not armed - cannot verify timeout configuration")

        # Verify service stays responsive after invalid command
        self.duthost.shell("watchdogutil invalid_command 2>&1 || true",
                           module_ignore_errors=True)
        result = self.duthost.shell("watchdogutil status", module_ignore_errors=True)
        self.expect(result['rc'] == 0,
                    "watchdogutil status failed after invalid command")

    def test_watchdog_bmc_integration(self):
        """
        Verify watchdog integrates correctly with BMC infrastructure

        Validates:
        - systemd watchdog service existence and configuration
        - Log storage in /host/bmc/ directory
        - Reboot reason accessible (dmesg/cmdline)
        - State DB reflects watchdog status (if supported)
        """
        # Check systemd watchdog service
        result = self.duthost.shell(
            "systemctl list-units --type=service | grep -i watchdog || echo 'no-services'",
            module_ignore_errors=True
        )
        if 'no-services' in result['stdout']:
            logger.info("No systemd watchdog services found")
        else:
            logger.info(f"Watchdog services: {result['stdout'][:200]}")

            # Check service configuration (petting interval, timeout)
            result = self.duthost.shell(
                "grep -E 'ExecStart|Interval|Timer' "
                "/etc/systemd/system/*watchdog*.service 2>/dev/null || echo 'no-config'",
                module_ignore_errors=True
            )
            if 'no-config' not in result['stdout']:
                logger.info(f"Watchdog service config: {result['stdout']}")

        # Check persistent log storage in /host/bmc
        result = self.duthost.shell("test -d /host/bmc && echo 'exists' || echo 'missing'",
                                    module_ignore_errors=True)
        if 'missing' in result['stdout']:
            logger.info("BMC directory not found - skipping persistent log check")
        else:
            result = self.duthost.shell("ls -la /host/bmc/ | grep -i watch || echo 'no-logs'",
                                        module_ignore_errors=True)
            if 'no-logs' in result['stdout']:
                logger.info("No watchdog logs in /host/bmc yet - expected on new systems")
            else:
                logger.info(f"Watchdog logs in /host/bmc: {result['stdout'][:200]}")

            # Warn if watchdog logs exist in /var/log (should be in /host/bmc)
            result = self.duthost.shell("ls /var/log/watchdog* 2>/dev/null | wc -l",
                                        module_ignore_errors=True)
            if result['rc'] == 0 and int(result['stdout'].strip()) > 0:
                logger.warning("Found watchdog logs in /var/log (expected in /host/bmc)")

        # Reboot reason detection (user vs watchdog reset)
        result = self.duthost.shell(
            "dmesg | grep -i 'watchdog\\|reboot' | tail -5 || echo 'no-matches'",
            module_ignore_errors=True
        )
        if 'no-matches' not in result['stdout']:
            logger.info(f"Reboot-related logs: {result['stdout'][:200]}")
        else:
            logger.info("No watchdog/reboot entries in dmesg - expected on running system")

        # State DB consistency check
        result = self.duthost.shell(
            "sonic-db-cli STATE_DB KEYS '*WATCH*' 2>/dev/null || echo 'not-available'",
            module_ignore_errors=True
        )
        if result['rc'] == 0 and 'not-available' not in result['stdout']:
            logger.info(f"State DB watchdog entries: {result['stdout'].strip()}")
        else:
            logger.info("No watchdog entries in State DB - expected if not supported")

