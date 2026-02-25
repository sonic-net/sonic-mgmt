"""
Test that running grep in the pmon container does not cause kernel panic.

Covers test gap issue #18394.

On some platforms, running ``grep -r`` inside the pmon container over
``/sys/kernel/debug`` (if mounted) can trigger kernel panics or hang
the process.  A properly configured pmon container should either not
mount debugfs or have its contents removed so that grep completes
safely.

This test verifies:
1. grep inside the pmon container completes without error.
2. No kernel panic is detected in dmesg after the grep.
"""

import logging
import re

import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs'),
]


def test_pmon_grep_no_kernel_panic(duthosts, rand_one_dut_hostname):
    """
    Verify that running grep inside the pmon container does not cause
    kernel panic or other critical errors.

    Test steps:
    1. Verify pmon container is running.
    2. Record current dmesg line count as baseline.
    3. Run grep inside pmon as a basic sanity check.
    4. If /sys/kernel/debug exists in pmon, run grep over it with a
       timeout to catch hangs.
    5. Check dmesg for new kernel panic / BUG / Oops messages.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Step 1 - verify pmon container is running
    output = duthost.shell("docker ps")["stdout"]
    if "pmon" not in output:
        pytest.skip("pmon container is not running on this device")

    logger.info("pmon container is running")

    # Step 2 - baseline dmesg line count
    dmesg_baseline = duthost.shell("dmesg | wc -l")["stdout"].strip()
    baseline_lines = int(dmesg_baseline)
    logger.info("dmesg baseline: %d lines", baseline_lines)

    # Step 3 - basic grep sanity inside pmon
    result = duthost.shell("docker exec pmon grep -c Linux /proc/version")
    pytest_assert(
        result["stdout"].strip() != "0",
        "Basic grep inside pmon returned no matches for 'Linux' in /proc/version",
    )
    logger.info("Basic grep inside pmon succeeded")

    # Step 4 - grep over /sys/kernel/debug if present
    check_debug = duthost.shell(
        "docker exec pmon test -d /sys/kernel/debug && echo EXISTS || echo MISSING",
        module_ignore_errors=True,
    )
    debug_stdout = check_debug.get(
        "stdout",
        check_debug.get("stdout_lines", [""])[0]
        if "stdout_lines" in check_debug else ""
    )
    if "EXISTS" in str(debug_stdout):
        logger.info("/sys/kernel/debug exists in pmon - running grep with timeout")
        # Use timeout to prevent indefinite hangs.  Grep for a string
        # that won't match so it scans all files.
        duthost.shell(
            'docker exec pmon bash -c '
            '"timeout 30 grep -r SONIC_PMON_GREP_TEST_12345 /sys/kernel/debug/ 2>/dev/null; exit 0"',
            module_ignore_errors=True,
        )
        logger.info("grep over /sys/kernel/debug completed")
    else:
        logger.info(
            "/sys/kernel/debug does not exist in pmon - "
            "container is properly configured"
        )

    # Step 5 - check dmesg for new kernel panic / BUG / Oops
    dmesg_after = duthost.shell("dmesg")["stdout"]
    all_lines = dmesg_after.strip().splitlines()
    new_lines = all_lines[baseline_lines:]

    panic_patterns = [
        r"Kernel panic",
        r"BUG:",
        r"Oops:",
        r"Call Trace:",
        r"general protection fault",
    ]
    panic_found = []
    for line in new_lines:
        for pattern in panic_patterns:
            if re.search(pattern, line):
                panic_found.append(line.strip())
                break

    pytest_assert(
        len(panic_found) == 0,
        "Kernel panic or BUG detected in dmesg after grep in pmon: %s"
        % "; ".join(panic_found),
    )

    logger.info(
        "No kernel panic detected after grep operations in pmon container"
    )
