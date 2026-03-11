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
import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical'),
    pytest.mark.disable_loganalyzer
]

GREP_CMD = 'docker exec pmon grep -r "test_string_placeholder" /sys/kernel/debug/'
DMESG_CMD = "dmesg --level=emerg,alert,crit -T"

KERNEL_PANIC_PATTERNS = [
    r"kernel\s*panic",
    r"Call\s*Trace",
    r"Oops",
    r"BUG:",
    r"RIP:.*\[",
]


def test_pmon_grep_no_kernel_panic(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    @summary: Verify that running grep inside the pmon container over
              /sys/kernel/debug does not cause a kernel panic.

              The test runs a harmless grep command inside pmon and then
              checks dmesg for any newly appeared critical kernel messages.

              Addresses: https://github.com/sonic-net/sonic-mgmt/issues/18394
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Capture dmesg baseline before the grep
    pre_dmesg = duthost.command(DMESG_CMD, module_ignore_errors=True)
    pre_line_count = len(pre_dmesg.get("stdout_lines", []))

    # Run grep inside pmon container — errors from grep itself are expected
    # (Invalid argument, Resource temporarily unavailable, etc.).
    # We only care that it does not crash the kernel.
    duthost.command(GREP_CMD, module_ignore_errors=True)

    # Check dmesg for any new critical messages after the grep
    post_dmesg = duthost.command(DMESG_CMD, module_ignore_errors=True)
    post_lines = post_dmesg.get("stdout_lines", [])

    # Only inspect lines that appeared after the grep
    new_lines = post_lines[pre_line_count:]
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
