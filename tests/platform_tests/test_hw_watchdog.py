"""
Test to verify hardware watchdog is enabled on the device.

This test addresses the test gaps described in:
https://github.com/sonic-net/sonic-mgmt/issues/21686
https://github.com/sonic-net/sonic-mgmt/issues/22491

SONiC requires the hardware watchdog to be enabled on all platforms.
This test validates that the watchdog utility is available, that
the hardware watchdog is armed, and that the remaining timeout is
within a sane range.

By default, an unarmed watchdog produces a warning and skips.
Use --strict_watchdog to make it a test failure.
"""
import logging
import re

import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical'),
    pytest.mark.disable_loganalyzer
]

WATCHDOG_STATUS_CMD = "watchdogutil status"
WATCHDOG_ARM_CMD = "watchdogutil arm"
WATCHDOG_DISARM_CMD = "watchdogutil disarm"

# Sane range for hardware watchdog timeout (seconds).
# Default arm timeout is 180s. Values outside 30-300s indicate
# misconfiguration that could cause premature reboots (<30s) or
# ineffective watchdog protection (>300s).
WATCHDOG_MIN_TIMEOUT = 30
WATCHDOG_MAX_TIMEOUT = 300


@pytest.fixture(scope="module")
def strict_watchdog(request):
    return request.config.getoption("--strict_watchdog")


@pytest.fixture
def ensure_watchdog_armed(duthosts, enum_rand_one_per_hwsku_hostname):
    """Ensure watchdog is armed for the test, restoring original state afterward.

    If watchdog is already armed, this is a no-op.
    If unarmed, arms it with default timeout (180s) and disarms after the test.
    Skips if watchdogutil is not supported on the platform.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.command(WATCHDOG_STATUS_CMD, module_ignore_errors=True)
    if result["rc"] != 0 or result["stdout"].strip() == "":
        pytest.skip("watchdogutil is not supported on this platform (rc={}, stderr='{}')".format(
            result["rc"], result["stderr"]))

    status_output = result["stdout"].strip().lower()
    was_armed = "armed" in status_output and "unarmed" not in status_output

    if not was_armed:
        logger.info("Watchdog is unarmed on '{}', arming for test".format(duthost.hostname))
        arm_result = duthost.command(WATCHDOG_ARM_CMD, module_ignore_errors=True)
        pytest_assert(arm_result["rc"] == 0,
                      "Failed to arm watchdog: {}".format(arm_result["stderr"]))

    yield was_armed

    if not was_armed:
        logger.info("Restoring watchdog to unarmed state on '{}'".format(duthost.hostname))
        duthost.command(WATCHDOG_DISARM_CMD, module_ignore_errors=True)


def test_hw_watchdog_supported(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify that the hardware watchdog utility is available on the DUT.
              The watchdogutil command must be present and return valid output.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.command(WATCHDOG_STATUS_CMD, module_ignore_errors=True)
    pytest_assert(result["rc"] == 0,
                  "watchdogutil command failed with rc={}: {}".format(
                      result["rc"], result["stderr"]))
    pytest_assert(result["stdout"].strip() != "",
                  "watchdogutil status returned empty output")


def test_hw_watchdog_armed(duthosts, enum_rand_one_per_hwsku_hostname, strict_watchdog):
    """
    @summary: Verify that the hardware watchdog is armed (enabled) on the DUT.
              SONiC requires the hardware watchdog to be enabled on all platforms
              to ensure the system can recover from hangs.

              By default, an unarmed watchdog logs a warning and skips.
              Pass --strict_watchdog to treat it as a failure.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.command(WATCHDOG_STATUS_CMD, module_ignore_errors=True)

    if result["rc"] != 0 or result["stdout"].strip() == "":
        pytest.skip("watchdogutil is not supported on this platform (rc={}, stderr='{}')".format(
            result["rc"], result["stderr"]))

    status_output = result["stdout"].strip().lower()

    if "unarmed" in status_output or "armed" not in status_output:
        msg = ("Hardware watchdog is not armed on '{}'. "
               "SONiC requires the hardware watchdog to be enabled. "
               "Output: {}".format(duthost.hostname, result["stdout"]))
        if strict_watchdog:
            pytest.fail(msg)
        else:
            logger.warning(msg)
            pytest.skip("Watchdog is not armed (use --strict_watchdog to enforce)")

    logger.info("Hardware watchdog is armed on '{}'".format(duthost.hostname))


def _parse_remaining_time(output):
    """Parse 'Time remaining: <N> seconds' from watchdogutil status output.

    Args:
        output: stdout from 'watchdogutil status'

    Returns:
        int or None: remaining time in seconds, or None if not found
    """
    match = re.search(r'Time remaining:\s*(\d+)\s*seconds', output)
    if match:
        return int(match.group(1))
    return None


def test_hw_watchdog_remaining_time(duthosts, enum_rand_one_per_hwsku_hostname, ensure_watchdog_armed):
    """
    @summary: Verify that the hardware watchdog remaining timeout is within
              a sane range (30-300 seconds).

              Platforms occasionally misconfigure absurdly short or long
              watchdog timeouts, which can cause either premature reboots
              (< 30s) or ineffective watchdog protection (> 300s).

              If watchdog is not armed, the fixture arms it temporarily
              and restores the original state after the test.

              This test addresses:
              https://github.com/sonic-net/sonic-mgmt/issues/22491
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.command(WATCHDOG_STATUS_CMD, module_ignore_errors=True)
    pytest_assert(result["rc"] == 0,
                  "watchdogutil status failed after arming: {}".format(result["stderr"]))

    status_output = result["stdout"].strip()

    remaining = _parse_remaining_time(status_output)
    pytest_assert(remaining is not None,
                  "Could not parse remaining time from watchdogutil output: {}".format(
                      status_output))

    logger.info("Watchdog remaining time on '{}': {} seconds".format(
        duthost.hostname, remaining))

    pytest_assert(remaining >= WATCHDOG_MIN_TIMEOUT,
                  "Watchdog remaining time {}s is below minimum {}s on '{}'. "
                  "This may cause premature reboots. Output: {}".format(
                      remaining, WATCHDOG_MIN_TIMEOUT, duthost.hostname, status_output))

    pytest_assert(remaining <= WATCHDOG_MAX_TIMEOUT,
                  "Watchdog remaining time {}s exceeds maximum {}s on '{}'. "
                  "This may indicate ineffective watchdog protection. Output: {}".format(
                      remaining, WATCHDOG_MAX_TIMEOUT, duthost.hostname, status_output))
