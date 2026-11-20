"""Conftest for Failure-Validated xfail integration tests.

Patches SIGNATURES_DIR to point to the test's own signatures/ directory
so test signature files don't pollute the real known_issue_signatures/ folder.

Copies the integration test mark conditions file to the real plugin directory
before collection so the conditional_mark plugin picks it up, and removes it
after the session ends.

Also provides shared helpers used by the test and wrapper modules.
"""

import atexit
import os
import re
import shutil
import sys
import logging

from tests.common.plugins.conditional_mark import failure_signature

logger = logging.getLogger(__name__)

_THIS_DIR = os.path.dirname(__file__)
_PLUGIN_DIR = os.path.dirname(os.path.realpath(failure_signature.__file__))

# Patch SIGNATURES_DIR to the test's own signatures/ directory
failure_signature.SIGNATURES_DIR = os.path.join(_THIS_DIR, "signatures")

# Copy the integration test mark conditions file to the plugin directory
# so load_conditions() picks it up during pytest_collection.
_MARK_CONDITIONS_SRC = os.path.join(_THIS_DIR, "tests_mark_conditions_fvxfail_integration.yaml")
_MARK_CONDITIONS_DST = os.path.join(_PLUGIN_DIR, "tests_mark_conditions_fvxfail_integration.yaml")

if os.path.isfile(_MARK_CONDITIONS_SRC):
    shutil.copy2(_MARK_CONDITIONS_SRC, _MARK_CONDITIONS_DST)
    logger.info(f"Installed integration test mark conditions: {_MARK_CONDITIONS_DST}")


def _cleanup_mark_conditions():
    if os.path.isfile(_MARK_CONDITIONS_DST):
        os.remove(_MARK_CONDITIONS_DST)
        logger.info(f"Removed integration test mark conditions: {_MARK_CONDITIONS_DST}")


atexit.register(_cleanup_mark_conditions)


# ---------------------------------------------------------------------------
# Shared helpers for test modules and wrapper modules
# ---------------------------------------------------------------------------

MOCKED_FAILURES_DIR = os.path.join(_PLUGIN_DIR, "integration_test", "mocked_failures")


def load_mocked_failure(name):
    """Load a mocked failure message from the mocked_failures/ directory."""
    with open(os.path.join(MOCKED_FAILURES_DIR, name)) as f:
        return f.read()


def build_pytest_cmd(test_file):
    """Build the pytest command reusing relevant args from the parent process.

    Filters out args that should not be inherited by the child subprocess:
    -k, --rootdir, --alluredir, --allure_server, --clean-alluredir, and
    args already set in the base command (-v, --tb, -ra, --log-cli-level).
    Sets --rootdir to the tests/ directory so the child discovers the correct
    conftest chain.
    """
    tests_dir = os.path.normpath(os.path.join(_THIS_DIR, "../../../.."))
    cmd = [sys.executable, "-u", "-m", "pytest", test_file, "-v", "--tb=short", "-ra",
           "--log-cli-level", "critical", "--rootdir", tests_dir]

    parent_args = sys.argv[1:]
    skip_next = False
    for arg in parent_args:
        if skip_next:
            skip_next = False
            continue
        # Skip test file arguments
        if arg.startswith("common/plugins/") or arg.startswith("test_"):
            continue
        # Skip allure-related args (don't want child to upload)
        if arg in ("--clean-alluredir",):
            continue
        if arg.startswith("--alluredir"):
            if "=" not in arg:
                skip_next = True
            continue
        if arg.startswith("--allure_server"):
            if "=" not in arg:
                skip_next = True
            continue
        # Skip args already in cmd or that we override
        if arg in ("-v", "--tb=short", "-ra"):
            continue
        if arg.startswith("--log-cli-level"):
            if "=" not in arg:
                skip_next = True
            continue
        # Skip -k (test selection) — the parent's -k (e.g. -k "wrapper")
        # would deselect all child tests since their names don't match.
        if arg == "-k":
            skip_next = True
            continue
        # Skip --rootdir — we set our own above for the child process
        if arg.startswith("--rootdir"):
            if arg == "--rootdir":
                skip_next = True
            continue
        cmd.append(arg)

    return cmd


def parse_summary(output):
    """Parse the pytest short test summary to extract outcomes and details.

    The summary format is:
        XFAIL ...::test_name - reason line 1
        reason line 2 (for multi-issue 'or' conditions)
        [Failure-Validated xfail: detail...]
        FAILED ...::test_name
        FAILED ...::test_name - detail

    Returns dict of {test_name: {"outcome": str, "detail": str}}
    """
    # Extract just the short test summary section
    lines = output.splitlines()
    summary_start = None
    summary_end = None
    for i, line in enumerate(lines):
        if "short test summary info" in line:
            summary_start = i + 1
        elif summary_start and line.startswith("====") and "passed" in line:
            summary_end = i
            break

    if summary_start is None:
        return {}

    summary_lines = lines[summary_start:summary_end]

    results = {}
    i = 0
    while i < len(summary_lines):
        line = summary_lines[i]

        # Match XFAIL line
        m = re.match(r'XFAIL\s+.*::(\w+)\s*-\s*(.*)', line)
        if m:
            test_name = m.group(1)
            detail = m.group(2)
            # Collect continuation lines (reason continuation or [FV-xfail detail])
            while i + 1 < len(summary_lines):
                next_line = summary_lines[i + 1]
                if next_line.startswith("XFAIL ") or next_line.startswith("FAILED "):
                    break
                i += 1
                detail += "\n" + next_line
            results[test_name] = {"outcome": "xfail", "detail": detail}
            i += 1
            continue

        # Match FAILED line
        m = re.match(r'FAILED\s+.*::(\w+)', line)
        if m:
            test_name = m.group(1)
            results[test_name] = {"outcome": "failed", "detail": ""}
            i += 1
            continue

        i += 1

    # Also parse the per-test result lines for PASSED tests
    # (PASSED tests don't appear in the short summary with -ra,
    #  so parse the verbose output lines)
    for line in lines:
        m = re.match(r'.*::(\w+)\s+PASSED', line)
        if m:
            test_name = m.group(1)
            if test_name not in results:
                results[test_name] = {"outcome": "passed", "detail": ""}

    return results
