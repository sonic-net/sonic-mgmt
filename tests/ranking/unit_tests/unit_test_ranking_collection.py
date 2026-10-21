import ast
import re
from pathlib import Path
from unittest.mock import Mock

import pytest

from tests.ranking import execution_config, lifecycle, ranking_infra, report_runner


pytest_plugins = ['pytester']
RANKING_ROOT = Path(__file__).resolve().parents[1]


def _world(pytester):
    pytester.makeconftest((RANKING_ROOT / 'conftest.py').read_text())
    pytester.makepyfile(test_ranking=(RANKING_ROOT / 'test_ranking.py').read_text())
    pytester.makeini('[pytest]\nmarkers =\n    topology(name): topology requirement\n')


@pytest.fixture
def boundaries(monkeypatch):
    monkeypatch.setenv('PYTEST_DISABLE_PLUGIN_AUTOLOAD', '1')
    loader = Mock(side_effect=AssertionError('unconfigured collection must not load execution inputs'))
    infra = Mock(side_effect=AssertionError('unconfigured collection must not construct Infra'))
    session = Mock(side_effect=AssertionError('unconfigured collection must not construct RankingSession'))
    report = Mock(side_effect=AssertionError('unconfigured collection must not generate a report'))
    monkeypatch.setattr(execution_config, 'load_execution_inputs', loader)
    monkeypatch.setattr(ranking_infra, 'Infra', infra)
    monkeypatch.setattr(lifecycle, 'RankingSession', session)
    monkeypatch.setattr(report_runner, 'build_report', report)
    return loader, infra, session, report


def _assert_unused(boundaries):
    for boundary in boundaries:
        boundary.assert_not_called()


def test_unconfigured_ranking_collects_without_loading_execution(pytester, boundaries):
    _world(pytester)
    result = pytester.runpytest('--collect-only', '-q', '--confcutdir=' + str(pytester.path))
    assert result.ret == 0
    result.stdout.fnmatch_lines(['*test_ranking_case*', '*1 test collected*'])
    _assert_unused(boundaries)


def test_unconfigured_ranking_skips_before_any_fixture_setup(pytester, boundaries):
    _world(pytester)
    pytester.makepyfile(test_unrelated='def test_unrelated():\n    assert True\n')
    result = pytester.runpytest('-q', '--confcutdir=' + str(pytester.path))
    result.assert_outcomes(passed=1, skipped=1)
    _assert_unused(boundaries)


@pytest.mark.parametrize('options', [
    ['--ranking-inputs=/unused/inputs'],
    ['--ranking-inputs='],
    ['--ranking-artifacts=/unused/artifacts'],
    ['--ranking-keep-env'],
    ['--ranking-environment-id=env-explicit'],
    ['--ranking-skip-setup', '--ranking-environment-id=env-explicit'],
])
def test_partial_ranking_configuration_still_errors(pytester, boundaries, options):
    _world(pytester)
    result = pytester.runpytest(
        '--collect-only', '-q', '--confcutdir=' + str(pytester.path), *options)
    assert result.ret == 2
    result.stdout.fnmatch_lines(['*ranking cases require --ranking-inputs and --ranking-artifacts*'])
    _assert_unused(boundaries)


def test_configured_ranking_still_runs_each_selected_case(pytester, boundaries):
    _world(pytester)
    loader, infra, session_constructor, report = boundaries
    selected = ['sairoute.RouteA', 'saivlan.VlanB']
    loader.side_effect = None
    loader.return_value = {'selected_cases': selected}
    infra.side_effect = None
    session_constructor.side_effect = None
    session = session_constructor.return_value
    report.side_effect = None
    report.return_value = {'status': 'complete'}
    artifacts = pytester.path / 'fresh-artifacts'
    result = pytester.runpytest(
        '-q', '--confcutdir=' + str(pytester.path),
        '--ranking-inputs=/prepared/inputs', '--ranking-artifacts=' + str(artifacts))
    result.assert_outcomes(passed=2)
    loader.assert_called_once_with('/prepared/inputs', str(artifacts))
    session.start.assert_called_once()
    assert [call.args[0] for call in session.run.call_args_list] == selected
    session.close.assert_called_once()


def test_controller_collection_never_imports_ptf_case_assets(pytester, boundaries):
    _world(pytester)
    assets = pytester.path / 'cases'
    assets.mkdir()
    (assets / 'sai_base_test.py').write_text("raise AssertionError('PTF assets imported on controller')\n")
    (assets / 'ext_sai_scale_test.py').write_text("raise AssertionError('PTF assets imported on controller')\n")
    result = pytester.runpytest('--collect-only', '-q', '--confcutdir=' + str(pytester.path))
    assert result.ret == 0
    result.stdout.fnmatch_lines(['*1 test collected*'])
    _assert_unused(boundaries)


def test_ranking_entry_has_the_community_ptf_topology_marker():
    source = (RANKING_ROOT / 'test_ranking.py').read_text()
    checker_path = RANKING_ROOT.parents[1] / '.azure-pipelines' / 'markers_check' / 'markers_check.py'
    checker = ast.parse(checker_path.read_text())
    pattern = next(node.value.args[0].value for node in ast.walk(checker)
                   if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'pattern'
                           for target in node.targets))
    assert re.search(pattern, source)
    namespace = {}
    exec(compile(source, str(RANKING_ROOT / 'test_ranking.py'), 'exec'), namespace)
    marks = namespace['pytestmark']
    assert any(mark.name == 'topology' and mark.args == ('ptf',) for mark in marks)
