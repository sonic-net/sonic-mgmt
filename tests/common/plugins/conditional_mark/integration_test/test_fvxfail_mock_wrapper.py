"""Wrapper test that runs the FV-xfail mock integration tests as a subprocess
and validates the pytest results.

This test runs test_fvxfail_mock.py via subprocess, parses the short test
summary, and asserts that each test case produced the expected outcome.

Usage:
    pytest common/plugins/conditional_mark/integration_test/test_fvxfail_mock_wrapper.py ...
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


# Expected outcomes for each test in test_fvxfail_mock.py
EXPECTED = {
    # Core Decision Logic
    "test_same_failure_high_similarity": {
        "outcome": "xfail",
        "detail_contains": ["high threshold", "same issue"],
    },
    "test_different_failure_low_similarity": {
        "outcome": "failed",
    },
    "test_no_signature_file_no_fvxfail": {
        "outcome": "failed",
    },
    "test_passed_no_interference": {
        "outcome": "passed",
    },
    # Threshold and Weight Overrides
    "test_custom_high_threshold": {
        "outcome": "xfail",
        "detail_contains": ["high threshold", "same issue"],
    },
    "test_custom_low_threshold": {
        "outcome": "failed",
    },
    "test_custom_weights": {
        "outcome": "xfail",
        "detail_contains": ["high threshold", "same issue"],
    },
    # Setup and Teardown Phases
    "test_setup_failure_same_issue": {
        "outcome": "xfail",
        "detail_contains": ["same issue"],
    },
    "test_teardown_failure_same_issue": {
        "outcome": "xfail",
        "detail_contains": ["same issue"],
    },
    # Invalid Signature File
    "test_missing_mandatory_field_static_xfail_with_note": {
        "outcome": "xfail",
        "detail_contains": ["no valid signatures could be loaded"],
    },
    # Multiple Issues
    "test_multi_issue_clear_winner": {
        "outcome": "xfail",
        "detail_contains": ["high threshold", "same issue"],
    },
    "test_multi_issue_all_below_low": {
        "outcome": "failed",
    },
    # AI Agent (Mock Server)
    "test_ai_returns_same_issue": {
        "outcome": "xfail",
        "detail_contains": ["AI agent decision: same_issue"],
    },
    "test_ai_returns_different_issue": {
        "outcome": "failed",
    },
    "test_ai_timeout": {
        "outcome": "xfail",
        "detail_contains": ["unavailable"],
    },
    "test_ai_error_500": {
        "outcome": "xfail",
        "detail_contains": ["unavailable"],
    },
    "test_ai_malformed_response": {
        "outcome": "xfail",
        "detail_contains": ["unavailable"],
    },
    "test_ai_disabled_fallback": {
        "outcome": "xfail",
        "detail_contains": ["not configured"],
    },
    # Multi-Issue AI Disambiguation
    "test_multi_issue_ai_one_match": {
        "outcome": "xfail",
        "detail_contains": ["AI agent decision: same_issue"],
    },
    "test_multi_issue_ai_none_match": {
        "outcome": "failed",
    },
    "test_multi_issue_ai_all_error": {
        "outcome": "xfail",
        "detail_contains": ["unavailable"],
    },
    # Edge Case
    "test_no_excinfo_fallback": {
        "outcome": "passed",
    },
}


def test_fvxfail_mock_all():
    """Run all mock FV-xfail tests and validate outcomes."""
    test_file = "common/plugins/conditional_mark/integration_test/test_fvxfail_mock.py"
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
        # Include the raw summary for debugging
        summary_section = ""
        in_summary = False
        for line in output.splitlines():
            if "short test summary" in line:
                in_summary = True
            if in_summary:
                summary_section += line + "\n"
        pytest.fail(f"FV-xfail mock integration test validation failed:\n"
                    f"{error_report}\n\n"
                    f"Raw summary:\n{summary_section[:2000]}")
