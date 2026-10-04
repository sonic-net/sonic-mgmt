"""Integration tests using the real AI agent service.

These tests hit the real AI agent at the URL configured in
failure_signature.XFAIL_AI_AGENT_URL. They validate that the end-to-end
flow works with a live LLM backend.

Run directly to see raw pytest results:
    pytest common/plugins/conditional_mark/integration_test/test_fvxfail_real_ai.py ...

Or run the wrapper test to validate results automatically:
    pytest common/plugins/conditional_mark/integration_test/test_fvxfail_real_ai_wrapper.py ...
"""

import pytest

from tests.common.plugins.conditional_mark.integration_test.conftest import load_mocked_failure

pytestmark = [pytest.mark.disable_memory_utilization, pytest.mark.skip_check_dut_health,
              pytest.mark.disable_loganalyzer]


def test_real_ai_same_issue():
    """Middle range score, real AI should say same_issue."""
    pytest.fail(load_mocked_failure("middle_range_failure.txt"))


def test_real_ai_multi_issue():
    """Two close-score issues, real AI should match one."""
    pytest.fail(load_mocked_failure("multi_issue_close_scores.txt"))
