import uuid
import warnings
from pathlib import Path

import pytest

from tests.ranking.execution_config import load_execution_inputs
from tests.ranking.lifecycle import RankingCaseError, RankingSession
from tests.ranking.ranking_infra import Infra
from tests.ranking.report_runner import build_report


# PTF loads these assets inside its runtime; controller-side pytest must not import them.
collect_ignore = ['cases']


def pytest_addoption(parser):
    group = parser.getgroup('ranking')
    group.addoption('--ranking-inputs', action='store', default=None, metavar='DIR',
                    help='compiled ranking inputs directory')
    group.addoption('--ranking-artifacts', action='store', default=None, metavar='DIR',
                    help='fresh local directory for ranking artifacts')
    group.addoption('--ranking-keep-env', action='store_true', default=False,
                    help='keep the ranking environment instead of tearing it down')
    group.addoption('--ranking-skip-setup', action='store_true', default=False,
                    help='resume an existing ranking environment instead of setup')
    group.addoption('--ranking-environment-id', action='store', default=None, metavar='ID',
                    help='explicit environment identity for the ranking session')


def pytest_configure(config):
    if (config.getoption('--ranking-skip-setup') and
            not config.getoption('--ranking-environment-id')):
        raise pytest.UsageError(
            '--ranking-skip-setup requires --ranking-environment-id')


def _execution(config):
    execution = getattr(config, '_ranking_execution', None)
    if execution is not None:
        return execution
    inputs = config.getoption('--ranking-inputs')
    artifacts = config.getoption('--ranking-artifacts')
    if inputs is None or artifacts is None:
        raise pytest.UsageError(
            'ranking cases require --ranking-inputs and --ranking-artifacts')
    execution = load_execution_inputs(inputs, artifacts)
    config._ranking_execution = execution
    return execution


def _environment_id(config):
    environment_id = config.getoption('--ranking-environment-id')
    if environment_id is None:
        environment_id = 'env-' + uuid.uuid4().hex
        config._ranking_environment_id = environment_id
    return environment_id


def pytest_generate_tests(metafunc):
    if 'ranking_case' not in metafunc.fixturenames:
        return
    config = metafunc.config
    configured = any(config.getoption(option) is not None for option in (
        '--ranking-inputs', '--ranking-artifacts', '--ranking-environment-id')) or any(
        config.getoption(option) for option in ('--ranking-keep-env', '--ranking-skip-setup'))
    if not configured:
        metafunc.parametrize('ranking_case', [pytest.param(
            None, id='not-configured', marks=pytest.mark.skip(
                reason='Ranking requires --ranking-inputs and --ranking-artifacts'))], indirect=True)
        return
    cases = list(_execution(metafunc.config)['selected_cases'])
    metafunc.parametrize('ranking_case', cases, ids=cases, indirect=True)


def pytest_sessionfinish(session, exitstatus):
    config = session.config
    execution = getattr(config, '_ranking_execution', None)
    artifacts = config.getoption('--ranking-artifacts')
    if execution is None or artifacts is None:
        return
    try:
        status = build_report(artifacts, execution['selected_cases'])
    except (OSError, TypeError, ValueError) as error:
        warnings.warn(
            pytest.PytestWarning('ranking report generation failed: {}'.format(error)))
        return
    config._ranking_report_status = status
    if status['status'] != 'complete':
        warnings.warn(pytest.PytestWarning(
            'ranking report is {}: {}'.format(
                status['status'], '; '.join(status['reasons']))))


@pytest.fixture(scope='session')
def ranking_infra():
    return Infra()


@pytest.fixture(scope='session')
def ranking_session(request, ranking_infra):
    config = request.config
    execution = _execution(config)
    artifacts = Path(config.getoption('--ranking-artifacts'))
    try:
        artifacts.mkdir(parents=True)
    except OSError as error:
        raise RuntimeError(
            'ranking artifacts directory cannot be created: {}'.format(error))
    session = RankingSession(
        ranking_infra,
        environment_id=_environment_id(config),
        keep=config.getoption('--ranking-keep-env'),
        skip_setup=config.getoption('--ranking-skip-setup'),
        execution=execution,
        artifacts_root=artifacts)
    request.addfinalizer(session.close)
    session.start()
    return session


@pytest.fixture
def ranking_case(request, ranking_session):
    case = request.param
    try:
        return {'case': case, 'result': ranking_session.run(case), 'error': None}
    except RankingCaseError as error:
        return {'case': case, 'result': error.result, 'error': error}
