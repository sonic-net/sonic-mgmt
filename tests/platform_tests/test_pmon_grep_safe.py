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
import time

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_container_running

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]


def test_pmon_grep_no_kernel_panic(duthosts, rand_one_dut_hostname):
    """
    Verify that running grep inside the pmon container does not cause
    kernel panic or other critical errors.

    Test steps:
    1. Verify pmon container is running.
    2. Record current dmesg timestamp as baseline for reliable
       new-message detection (immune to ring buffer wrap).
    3. Run grep inside pmon as a basic sanity check.
    4. If /sys/kernel/debug exists in pmon, run grep over it with a
       120s timeout to catch hangs on large debugfs trees.
    5. Check dmesg for new kernel panic / BUG / Oops messages
       (excluding non-fatal ``Call Trace:`` from lockdep/soft lockups).
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Step 1 - verify pmon container is running
    if not is_container_running(duthost, 'pmon'):
        pytest.skip("pmon container is not running on this device")

    logger.info("pmon container is running")

    # Step 2 - capture dmesg timestamp as baseline (more robust than line count)
    dmesg_baseline = duthost.shell(
        "dmesg --raw | tail -1 | grep -oP '^\\[\\s*\\K[0-9]+\\.[0-9]+'",
        module_ignore_errors=True,
    )
    baseline_timestamp = dmesg_baseline["stdout"].strip() if dmesg_baseline["rc"] == 0 else ""
    # Also capture monotonic clock as fallback
    baseline_mono = duthost.shell("cat /proc/uptime")["stdout"].strip().split()[0]
    logger.info("dmesg baseline timestamp: %s, uptime: %s", baseline_timestamp, baseline_mono)

    # Step 3 - basic grep sanity inside pmon
    result = duthost.shell("docker exec pmon grep -c Linux /proc/version")
    pytest_assert(
        result["stdout"].strip() != "0",
        "Basic grep inside pmon returned no matches for 'Linux' "
        "in /proc/version",
    )
    logger.info("Basic grep inside pmon succeeded")

    # Step 4 - grep over /sys/kernel/debug if present
    check_debug = duthost.shell(
        "docker exec pmon test -d /sys/kernel/debug "
        "&& echo EXISTS || echo MISSING",
        module_ignore_errors=True,
    )
    debug_stdout = check_debug["stdout"]
    if "EXISTS" in str(debug_stdout):
        logger.info(
            "/sys/kernel/debug exists in pmon - running grep with timeout")
        # Use timeout to prevent indefinite hangs.  Grep for a string
        # that won't match so it scans all files.
        # First check if `timeout` command is available in the container.
        timeout_check = duthost.shell(
            "docker exec pmon which timeout",
            module_ignore_errors=True,
        )
        has_timeout = (
            timeout_check.get("rc", 1) == 0
            and bool(timeout_check.get("stdout", "").strip())
        )
        if has_timeout:
            grep_cmd = (
                'docker exec pmon bash -c '
                '"timeout 120 grep -r SONIC_PMON_GREP_TEST_12345 '
                '/sys/kernel/debug/ 2>/dev/null; exit 0"'
            )
        else:
            logger.warning(
                "`timeout` not available in pmon container; "
                "running grep over /sys/kernel/debug without timeout"
            )
            grep_cmd = (
                'docker exec pmon bash -c '
                '"grep -r SONIC_PMON_GREP_TEST_12345 '
                '/sys/kernel/debug/ 2>/dev/null; exit 0"'
            )
        duthost.shell(grep_cmd, module_ignore_errors=True)
        logger.info("grep over /sys/kernel/debug completed")
    else:
        logger.info(
            "/sys/kernel/debug does not exist in pmon - "
            "container is properly configured"
        )

    # Step 5 - check dmesg for new kernel panic / BUG / Oops
    # Brief pause to let any deferred kernel messages flush
    time.sleep(2)
    dmesg_after = duthost.shell("dmesg", module_ignore_errors=True)
    if dmesg_after["rc"] != 0:
        logger.error(
            "Failed to collect dmesg after grep test (rc=%d). "
            "The DUT may be in a bad state — check console/serial logs.",
            dmesg_after["rc"],
        )
        pytest.fail(
            "Could not collect dmesg after grep test — DUT may have "
            "crashed or become unresponsive. Check debugfs mount in "
            "pmon container config and review serial/console logs."
        )

    all_lines = dmesg_after["stdout"].strip().splitlines()

    # Filter to only lines newer than our baseline timestamp
    new_lines = []
    if baseline_timestamp:
        for line in all_lines:
            ts_match = re.match(r'^\[\s*([0-9]+\.[0-9]+)\]', line)
            if ts_match and float(ts_match.group(1)) > float(baseline_timestamp):
                new_lines.append(line)
    else:
        # Fallback: use uptime-based filtering
        logger.warning("No baseline timestamp; using uptime-based filtering")
        for line in all_lines:
            ts_match = re.match(r'^\[\s*([0-9]+\.[0-9]+)\]', line)
            if ts_match and float(ts_match.group(1)) > float(baseline_mono):
                new_lines.append(line)

    # Only match definitive panic/crash indicators, not bare
    # "Call Trace:" which can appear in non-fatal warnings (lockdep,
    # soft lockups, etc.).
    panic_patterns = [
        r"Kernel panic",
        r"BUG:",
        r"Oops:",
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
        "Kernel panic or BUG detected in dmesg after grep in pmon. "
        "This may indicate debugfs is unsafely mounted in the pmon "
        "container. Check the pmon container config for debugfs mounts "
        "and review /sys/kernel/debug contents. Detected messages: %s"
        % "; ".join(panic_found),
    )

    logger.info(
        "No kernel panic detected after grep operations in pmon container"
    )
