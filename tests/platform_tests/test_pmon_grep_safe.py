"""
Test to verify that running grep inside the pmon container does not
trigger a kernel panic or other serious kernel errors.

Addresses the test gap described in:
https://github.com/sonic-net/sonic-mgmt/issues/18394

On some platforms (e.g. Cisco 8800 chassis), running ``grep -r`` inside
the pmon container over ``/sys/kernel/debug`` could trigger a kernel
panic.  The fix is to ensure the debug filesystem is not mounted or
its contents are removed inside the pmon container.  This test validates
that the fix is in place across all platforms.
"""
import logging
import re
import time
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_container_running

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical'),
    pytest.mark.disable_loganalyzer
]

# The search string is intentionally a dummy — the kernel panic is triggered by
# traversing /sys/kernel/debug, not by matching any particular content.
GREP_CMD = 'docker exec pmon grep -r "PMON_GREP_SAFE_TEST" /sys/kernel/debug/'
DMESG_CMD = "dmesg --level=emerg,alert,crit"

KERNEL_PANIC_PATTERNS = [
    r"kernel\s*panic",
    r"Call\s*Trace",
    r"Oops",
    r"BUG:",
    r"RIP:.*\[",
]

# Seconds to wait after grep before checking dmesg, giving the kernel time to
# flush any panic indicators to the log buffer.
POST_GREP_SETTLE_SECS = 5


def test_pmon_grep_no_kernel_panic(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify that running grep inside the pmon container over
              /sys/kernel/debug does not cause a kernel panic.

              The test runs a harmless grep command inside pmon and then
              checks dmesg for any newly appeared critical kernel messages.

              Addresses: https://github.com/sonic-net/sonic-mgmt/issues/18394
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Pre-check: pmon container must be running, otherwise the grep is a no-op
    pytest_assert(is_container_running(duthost, "pmon"),
                  "pmon container is not running on '{}'".format(duthost.hostname))

    # Record a timestamp before the grep so we can filter dmesg to only new messages
    timestamp_result = duthost.command("date '+%Y-%m-%dT%H:%M:%S'", module_ignore_errors=True)
    pre_timestamp = timestamp_result.get("stdout", "").strip()

    # Run grep inside pmon container — errors from grep itself are expected
    # (Invalid argument, Resource temporarily unavailable, etc.).
    # We only care that it does not crash the kernel.
    duthost.command(GREP_CMD, module_ignore_errors=True)

    # Allow kernel time to flush any panic indicators to the log buffer
    time.sleep(POST_GREP_SETTLE_SECS)

    # Check dmesg for any new critical messages since our timestamp
    post_dmesg_cmd = "dmesg --level=emerg,alert,crit --since='{}'".format(pre_timestamp)
    post_dmesg = duthost.command(post_dmesg_cmd, module_ignore_errors=True)
    new_lines = post_dmesg.get("stdout_lines", [])

    if not new_lines:
        logger.info("No new critical kernel messages after pmon grep on '{}'".format(
            duthost.hostname))
        return

    combined = "\n".join(new_lines)
    for pattern in KERNEL_PANIC_PATTERNS:
        match = re.search(pattern, combined, re.IGNORECASE)
        pytest_assert(match is None,
                      "Kernel panic indicator '{}' found in dmesg after running "
                      "grep in pmon container on '{}': {}".format(
                          pattern, duthost.hostname, combined))

    logger.info("No kernel panic detected after pmon grep on '{}'".format(
        duthost.hostname))
