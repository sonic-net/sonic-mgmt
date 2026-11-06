"""Explicit orchestration entry for the three independent Prepare actions."""

import pytest

from tests.ranking.prepare.case_sync import sync_cases


pytestmark = [
    pytest.mark.topology('ptf'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]


def test_prepare_workflow(ranking_prepare_context):
    context = ranking_prepare_context
    description = context.driver.describe(context)
    if 'configure_env' in context.steps:
        context.driver.configure_env(context, description)
    if 'check_env' in context.steps:
        context.driver.check_env(context, description)
    if 'sync_cases' in context.steps:
        sync_cases(context, description)
