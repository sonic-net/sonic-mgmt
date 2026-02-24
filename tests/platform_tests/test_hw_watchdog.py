"""
Test to verify hardware watchdog is enabled on the device.

This test addresses the test gap described in:
https://github.com/sonic-net/sonic-mgmt/issues/21686

SONiC requires the hardware watchdog to be enabled on all platforms.
This test validates that the watchdog utility is available and that
the hardware watchdog is armed.

By default, an unarmed watchdog produces a warning and skips.
Use --strict_watchdog to make it a test failure.
"""
import logging
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
