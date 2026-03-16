"""
Test to verify hardware watchdog is enabled on the device.

This test addresses the test gap described in:
https://github.com/sonic-net/sonic-mgmt/issues/21686
https://github.com/sonic-net/sonic-mgmt/issues/22491

SONiC requires the hardware watchdog to be enabled on all platforms.
This test validates that the watchdog utility is available, that
the hardware watchdog is armed, and that the remaining timeout is
within a reasonable range.

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


@pytest.fixture(scope="module")
def strict_watchdog(request):
    return request.config.getoption("--strict_watchdog")


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


# Reasonable range for watchdog timeout (seconds).
# The default arm timeout in SONiC is 180s; values outside 30-300s
# indicate a misconfiguration that could cause premature reboots or
# ineffective watchdog protection.
MIN_REMAINING_TIME = 30
MAX_REMAINING_TIME = 300


def test_hw_watchdog_remaining_time(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify that the hardware watchdog remaining time is within a
              reasonable range (30-300 seconds).

              Platforms occasionally misconfigure absurdly short or long
              watchdog timeouts. This test catches such misconfigurations.

              Addresses: https://github.com/sonic-net/sonic-mgmt/issues/22491
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.command(WATCHDOG_STATUS_CMD, module_ignore_errors=True)

    if result["rc"] != 0 or result["stdout"].strip() == "":
        pytest.skip("watchdogutil is not supported on this platform")

    status_output = result["stdout"].strip()

    if "Unarmed" in status_output or "Armed" not in status_output:
        pytest.skip("Watchdog is not armed; cannot check remaining time")

    # Parse "Time remaining: <N> seconds" from watchdogutil status output
    match = re.search(r"Time remaining:\s*(\d+)\s*seconds", status_output)
    pytest_assert(match is not None,
                  "Could not parse remaining time from watchdogutil output: {}".format(status_output))

    remaining = int(match.group(1))
    logger.info("Watchdog remaining time on '{}': {} seconds".format(duthost.hostname, remaining))

    pytest_assert(remaining >= MIN_REMAINING_TIME,
                  "Watchdog remaining time {}s is below minimum {}s on '{}'".format(
                      remaining, MIN_REMAINING_TIME, duthost.hostname))
    pytest_assert(remaining <= MAX_REMAINING_TIME,
                  "Watchdog remaining time {}s exceeds maximum {}s on '{}'".format(
                      remaining, MAX_REMAINING_TIME, duthost.hostname))
