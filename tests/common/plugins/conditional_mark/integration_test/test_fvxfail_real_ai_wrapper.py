"""Wrapper test that runs the FV-xfail real AI integration tests as a
subprocess and validates the pytest results.

Usage:
    pytest common/plugins/conditional_mark/integration_test/test_fvxfail_real_ai_wrapper.py ...
"""

import os
import subprocess
import pytest

from tests.common.plugins.conditional_mark.integration_test.conftest import (
    build_pytest_cmd, parse_summary,
)

pytestmark = [pytest.mark.disable_memory_utilization, pytest.mark.skip_check_dut_health,
              pytest.mark.disable_loganalyzer]

_THIS_DIR = os.path.dirname(__file__)


EXPECTED = {
    "test_real_ai_same_issue": {
        "outcome": "xfail",
        "detail_contains": ["AI agent decision: same_issue"],
    },
    "test_real_ai_multi_issue": {
        "outcome": "xfail",
        "detail_contains": ["AI agent decision: same_issue"],
    },
}


def test_fvxfail_real_ai_all():
    """Run all real AI FV-xfail tests and validate outcomes."""
    test_file = "common/plugins/conditional_mark/integration_test/test_fvxfail_real_ai.py"
    cmd = build_pytest_cmd(test_file)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=600,
        cwd=os.path.join(_THIS_DIR, "../../../.."),
        env=env,
    )

    output = result.stdout + result.stderr
    parsed = parse_summary(output)

    errors = []

    for test_name, expected in EXPECTED.items():
        if test_name not in parsed:
            errors.append(f"{test_name}: not found in results")
            continue

        actual = parsed[test_name]
        expected_outcome = expected["outcome"]

        if actual["outcome"] != expected_outcome:
            errors.append(f"{test_name}: expected {expected_outcome}, "
                          f"got {actual['outcome']}")

        if "detail_contains" in expected:
            for keyword in expected["detail_contains"]:
                if keyword not in actual["detail"]:
                    errors.append(
                        f"{test_name}: expected '{keyword}' in detail, "
                        f"not found. detail='{actual['detail'][:200]}'")

    if errors:
        error_report = "\n".join(errors)
        summary_section = ""
        in_summary = False
        for line in output.splitlines():
            if "short test summary" in line:
                in_summary = True
            if in_summary:
                summary_section += line + "\n"
        pytest.fail(f"FV-xfail real AI integration test validation failed:\n"
                    f"{error_report}\n\n"
                    f"Raw summary:\n{summary_section[:2000]}")
