from unittest.mock import Mock
import json
import re
import sys
from pathlib import Path

import pytest

from tests.ranking import conftest as ranking_plugin
from tests.ranking.lifecycle import RankingSession, RankingSetupError, RankingCaseError
from tests.ranking.ranking_infra import RoleResult

pytest_plugins = ['pytester']


def test_setup_failure_does_not_duplicate_rollback():
    infra = Mock()
    infra.call.return_value = RoleResult(2, {
        'rollback_attempted': True, 'ownership_state': 'retained'})
    session = RankingSession(infra, environment_id='env-a',
                             keep=False, skip_setup=False)
    with pytest.raises(RankingSetupError):
        session.start()
    session.close()
    assert [call.args[0] for call in infra.call.call_args_list] == ['setup']


def test_each_case_runs_and_finalizes_once():
    infra = Mock()
    infra.call.side_effect = [RoleResult(0, {}), RoleResult(7, {'rc': 7}),
                              RoleResult(0, {'rc': 0}), RoleResult(0, {})]
    session = RankingSession(infra, environment_id='env-a',
                             keep=False, skip_setup=False)
    session.start()
    with pytest.raises(RankingCaseError):
        session.run('sairoute.RouteA')
    session.run('sairoute.RouteB')
    session.close()
    session.close()
    assert [call.args[0] for call in infra.call.call_args_list] == [
        'setup', 'run', 'run', 'teardown']


def test_run_calls_carry_case_and_unique_run_ids():
    infra = Mock()
    infra.call.side_effect = [RoleResult(0, {}), RoleResult(0, {}),
                              RoleResult(0, {}), RoleResult(0, {})]
    session = RankingSession(infra, environment_id='env-a',
                             keep=False, skip_setup=False)
    session.start()
    session.run('sairoute.RouteA')
    session.run('sairoute.RouteB')
    session.close()
    run_calls = [call for call in infra.call.call_args_list
                 if call.args[0] == 'run']
    assert [call.kwargs['case'] for call in run_calls] == [
        'sairoute.RouteA', 'sairoute.RouteB']
    run_ids = [call.kwargs['run_id'] for call in run_calls]
    assert len(set(run_ids)) == 2
    assert all(re.fullmatch(r'[A-Za-z0-9_-]+', run_id) for run_id in run_ids)
    finalizer = infra.call.call_args_list[-1]
    assert finalizer.kwargs['case'] is None
    assert finalizer.kwargs['run_id'] is None


def test_every_call_shares_the_session_identity():
    infra = Mock()
    infra.call.side_effect = [RoleResult(0, {}), RoleResult(0, {}),
                              RoleResult(0, {}), RoleResult(0, {})]
    session = RankingSession(infra, environment_id='env-a', keep=False,
                             skip_setup=False, execution={'runtime': {}},
                             operation_id='op-7')
    session.start()
    session.run('sairoute.RouteA')
    session.close()
    for call in infra.call.call_args_list:
        assert call.kwargs['environment_id'] == 'env-a'
        assert call.kwargs['operation_id'] == 'op-7'
        assert call.kwargs['execution'] == {'runtime': {}}


def test_keep_closes_with_keep_and_not_teardown():
    infra = Mock()
    infra.call.side_effect = [RoleResult(0, {}), RoleResult(0, {}),
                              RoleResult(0, {})]
    session = RankingSession(infra, environment_id='env-a', keep=True,
                             skip_setup=False)
    session.start()
    session.run('sairoute.RouteA')
    session.close()
    assert [call.args[0] for call in infra.call.call_args_list] == [
        'setup', 'run', 'keep']


def test_skip_setup_starts_with_status():
    infra = Mock()
    infra.call.side_effect = [RoleResult(0, {}), RoleResult(0, {}),
                              RoleResult(0, {})]
    session = RankingSession(infra, environment_id='env-a', keep=False,
                             skip_setup=True)
    session.start()
    session.run('sairoute.RouteA')
    session.close()
    assert [call.args[0] for call in infra.call.call_args_list] == [
        'status', 'run', 'teardown']


def test_close_before_start_makes_no_calls():
    infra = Mock()
    session = RankingSession(infra, environment_id='env-a', keep=False,
                             skip_setup=False)
    session.close()
    infra.call.assert_not_called()


def test_run_before_start_is_rejected():
    infra = Mock()
    session = RankingSession(infra, environment_id='env-a', keep=False,
                             skip_setup=False)
    with pytest.raises(RuntimeError):
        session.run('sairoute.RouteA')
    infra.call.assert_not_called()


def test_setup_failure_keeps_the_role_outcome():
    infra = Mock()
    infra.call.return_value = RoleResult(2, {'ownership_state': 'retained'})
    session = RankingSession(infra, environment_id='env-a', keep=False,
                             skip_setup=False)
    with pytest.raises(RankingSetupError) as failure:
        session.start()
    assert failure.value.result.rc == 2
    assert failure.value.result.outcome == {'ownership_state': 'retained'}


def test_case_error_carries_the_case_and_role_outcome():
    infra = Mock()
    infra.call.side_effect = [RoleResult(0, {}), RoleResult(7, {'rc': 7}),
                              RoleResult(0, {}), RoleResult(0, {})]
    session = RankingSession(infra, environment_id='env-a', keep=False,
                             skip_setup=False)
    session.start()
    with pytest.raises(RankingCaseError) as failure:
        session.run('sairoute.RouteA')
    assert failure.value.case == 'sairoute.RouteA'
    assert failure.value.result.rc == 7


def test_finalize_failure_is_raised_and_not_retried():
    infra = Mock()
    infra.call.side_effect = [RoleResult(0, {}), RoleResult(0, {}),
                              RoleResult(3, {'uncertain': True})]
    session = RankingSession(infra, environment_id='env-a', keep=False,
                             skip_setup=False)
    session.start()
    session.run('sairoute.RouteA')
    with pytest.raises(RuntimeError):
        session.close()
    session.close()
    assert [call.args[0] for call in infra.call.call_args_list] == [
        'setup', 'run', 'teardown']


def test_artifacts_directories_are_distinct_per_call(tmp_path):
    infra = Mock()
    infra.call.side_effect = [RoleResult(0, {}), RoleResult(0, {}),
                              RoleResult(0, {}), RoleResult(0, {})]
    session = RankingSession(infra, environment_id='env-a', keep=False,
                             skip_setup=False, artifacts_root=tmp_path)
    session.start()
    session.run('sairoute.RouteA')
    session.run('sairoute.RouteB')
    session.close()
    paths = [call.kwargs['artifacts'] for call in infra.call.call_args_list]
    assert len(set(paths)) == 4
    for path in paths:
        assert str(tmp_path) in path


def test_session_rejects_invalid_environment_identities():
    for environment_id in ('', None, 'env a', 'env/a'):
        with pytest.raises(ValueError):
            RankingSession(Mock(), environment_id=environment_id, keep=False,
                           skip_setup=False)


def test_session_forwards_the_setup_receipt_to_the_finalizer(tmp_path):
    for keep, action in ((True, 'keep'), (False, 'teardown')):
        infra = Mock()
        infra.call.side_effect = [RoleResult(0, {}), RoleResult(0, {}),
                                  RoleResult(0, {})]
        session = RankingSession(infra, environment_id='env-a', keep=keep,
                                 skip_setup=False, artifacts_root=tmp_path)
        session.start()
        session.run('sairoute.RouteA')
        session.close()
        finalizer = infra.call.call_args_list[-1]
        assert finalizer.args[0] == action
        assert Path(finalizer.kwargs['receipt']) == (
            tmp_path / 'setup-1' / 'env-a' / 'environment-receipt.json')


def test_resumed_session_closes_without_a_controller_receipt(tmp_path):
    infra = Mock()
    infra.call.side_effect = [RoleResult(0, {}), RoleResult(0, {}),
                              RoleResult(0, {})]
    session = RankingSession(infra, environment_id='env-a', keep=False,
                             skip_setup=True, artifacts_root=tmp_path)
    session.start()
    session.run('sairoute.RouteA')
    session.close()
    finalizer = infra.call.call_args_list[-1]
    assert finalizer.args[0] == 'teardown'
    assert 'receipt' not in finalizer.kwargs


RECORD_NAME = 'infra-record.jsonl'
CASE_MODULES = ('sairoute', 'saivlan', 'sai_thrift', 'ptf')
SELECTED_CASES = ['sairoute.RouteA', 'sairoute.RouteB']


def _fake_infra_conftest(results):
    return '''import json
import os

import pytest

from tests.ranking.ranking_infra import RoleResult

pytest_plugins = ['tests.ranking.conftest']

RECORD = os.path.join(os.path.dirname(__file__), {record_name!r})
RESULTS = {results!r}


class FakeRankingInfra:
    def __init__(self):
        self.count = 0

    def call(self, action, **kwargs):
        record = {{'action': action, 'case': kwargs.get('case'),
                   'run_id': kwargs.get('run_id'),
                   'environment_id': kwargs.get('environment_id')}}
        with open(RECORD, 'a') as handle:
            handle.write(json.dumps(record) + chr(10))
        result = RoleResult(RESULTS[self.count], {{}})
        self.count += 1
        return result


@pytest.fixture(scope='session')
def ranking_infra():
    return FakeRankingInfra()
'''.format(record_name=RECORD_NAME, results=results)


def _ranking_world(pytester, results):
    source = Path(__file__).resolve().parents[1] / 'test_ranking.py'
    pytester.makeconftest(_fake_infra_conftest(results))
    pytester.path.joinpath('test_ranking.py').write_text(source.read_text())
    inputs = pytester.path / 'inputs'
    inputs.mkdir()
    return inputs, pytester.path / 'artifacts'


def _recorded_calls(pytester):
    path = pytester.path / RECORD_NAME
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_plugin_parametrizes_and_runs_the_manifest_cases(pytester, monkeypatch):
    inputs, artifacts = _ranking_world(pytester, [0, 7, 0, 0])
    monkeypatch.setattr(ranking_plugin, 'load_execution_inputs',
                        lambda inputs_dir, artifact_dir: {
                            'selected_cases': list(SELECTED_CASES), 'runtime': {}})
    result = pytester.runpytest(
        '--ranking-inputs=' + str(inputs), '--ranking-artifacts=' + str(artifacts),
        '--confcutdir=' + str(pytester.path), '-p', 'no:cacheprovider')
    result.assert_outcomes(failed=1, passed=1)
    record = _recorded_calls(pytester)
    assert [entry['action'] for entry in record] == [
        'setup', 'run', 'run', 'teardown']
    assert [entry['case'] for entry in record] == [
        None, 'sairoute.RouteA', 'sairoute.RouteB', None]
    assert len({entry['run_id'] for entry in record[1:3]}) == 2
    assert len({entry['environment_id'] for entry in record}) == 1
    assert artifacts.is_dir()
    assert not any(name in sys.modules for name in CASE_MODULES)


def test_keep_env_closes_without_teardown(pytester, monkeypatch):
    inputs, artifacts = _ranking_world(pytester, [0, 7, 0, 0])
    monkeypatch.setattr(ranking_plugin, 'load_execution_inputs',
                        lambda inputs_dir, artifact_dir: {
                            'selected_cases': list(SELECTED_CASES), 'runtime': {}})
    result = pytester.runpytest(
        '--ranking-inputs=' + str(inputs), '--ranking-artifacts=' + str(artifacts),
        '--ranking-keep-env', '--confcutdir=' + str(pytester.path),
        '-p', 'no:cacheprovider')
    result.assert_outcomes(failed=1, passed=1)
    record = _recorded_calls(pytester)
    assert [entry['action'] for entry in record] == [
        'setup', 'run', 'run', 'keep']


def test_setup_failure_errors_every_case_without_running_them(
        pytester, monkeypatch):
    inputs, artifacts = _ranking_world(pytester, [2])
    monkeypatch.setattr(ranking_plugin, 'load_execution_inputs',
                        lambda inputs_dir, artifact_dir: {
                            'selected_cases': list(SELECTED_CASES), 'runtime': {}})
    result = pytester.runpytest(
        '--ranking-inputs=' + str(inputs), '--ranking-artifacts=' + str(artifacts),
        '--confcutdir=' + str(pytester.path), '-p', 'no:cacheprovider')
    result.assert_outcomes(errors=2)
    record = _recorded_calls(pytester)
    assert [entry['action'] for entry in record] == ['setup']


def test_finalizer_failure_is_recorded_without_replacing_the_case_failure(
        pytester, monkeypatch):
    inputs, artifacts = _ranking_world(pytester, [0, 7, 0, 3])
    monkeypatch.setattr(ranking_plugin, 'load_execution_inputs',
                        lambda inputs_dir, artifact_dir: {
                            'selected_cases': list(SELECTED_CASES), 'runtime': {}})
    result = pytester.runpytest(
        '--ranking-inputs=' + str(inputs), '--ranking-artifacts=' + str(artifacts),
        '--confcutdir=' + str(pytester.path), '-p', 'no:cacheprovider')
    result.assert_outcomes(failed=1, passed=1, errors=1)
    result.stdout.fnmatch_lines(
        ['*ranking case sairoute.RouteA failed with rc 7*'])


def test_skip_setup_without_environment_id_is_a_usage_error(
        pytester, monkeypatch):
    inputs, artifacts = _ranking_world(pytester, [0, 0, 0, 0])
    monkeypatch.setattr(ranking_plugin, 'load_execution_inputs',
                        lambda inputs_dir, artifact_dir: {
                            'selected_cases': list(SELECTED_CASES), 'runtime': {}})
    result = pytester.runpytest(
        '--ranking-inputs=' + str(inputs), '--ranking-artifacts=' + str(artifacts),
        '--ranking-skip-setup', '--confcutdir=' + str(pytester.path),
        '-p', 'no:cacheprovider')
    assert result.ret == 4
    assert _recorded_calls(pytester) == []


def test_source_mismatch_aborts_before_any_setup(pytester, monkeypatch):
    inputs, artifacts = _ranking_world(pytester, [0, 0, 0, 0])

    def broken(inputs_dir, artifact_dir):
        raise ValueError('manifest source identity mismatch')

    monkeypatch.setattr(ranking_plugin, 'load_execution_inputs', broken)
    result = pytester.runpytest(
        '--ranking-inputs=' + str(inputs), '--ranking-artifacts=' + str(artifacts),
        '--confcutdir=' + str(pytester.path), '-p', 'no:cacheprovider')
    assert result.ret == 2
    assert _recorded_calls(pytester) == []


def test_skip_setup_resumes_the_kept_environment(pytester, monkeypatch):
    inputs, artifacts = _ranking_world(pytester, [0, 0, 0, 0])
    monkeypatch.setattr(ranking_plugin, 'load_execution_inputs',
                        lambda inputs_dir, artifact_dir: {
                            'selected_cases': list(SELECTED_CASES), 'runtime': {}})
    result = pytester.runpytest(
        '--ranking-inputs=' + str(inputs), '--ranking-artifacts=' + str(artifacts),
        '--ranking-skip-setup', '--ranking-environment-id=env-a',
        '--confcutdir=' + str(pytester.path), '-p', 'no:cacheprovider')
    result.assert_outcomes(passed=2)
    record = _recorded_calls(pytester)
    assert [entry['action'] for entry in record] == [
        'status', 'run', 'run', 'teardown']
    assert {entry['environment_id'] for entry in record} == {'env-a'}
