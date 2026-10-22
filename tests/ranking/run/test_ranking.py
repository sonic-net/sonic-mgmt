import pytest

from tests.ranking.run.case_executor import InfrastructureError, execute


pytestmark = [
    pytest.mark.topology('ptf'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]


def test_ranking_case(ranking_case, ranking_session, request):
    """Map one normalized executor result into pytest semantics."""
    batch = ranking_session
    try:
        result = execute(
            batch['ptf'], batch['config'], batch['session'], ranking_case,
            batch['output_root'],
            live_log=request.config.getoption('--ranking-live-log'))
    except InfrastructureError:
        request.session.shouldstop = (
            'Ranking infrastructure state is uncertain; stop remaining cases')
        raise
    if result['status'] == 'skipped':
        pytest.skip('Original PTF case reported skipped')
    assert result['status'] == 'passed', (
        'PTF failed; inspect {}'.format(result['log_path']))
