import hashlib
import json

import pytest


CASE = 'sairoute.multipleRoutesTest'


def _config():
    return {
        'ptf_executable': '/SAI-TEST/test/ptf/ptf',
        'ptf_arguments': ['--relax'],
        'ptf_workdir': '/SAI-TEST',
        'ptf_case_dir': '/SAI-TEST/ptf',
        'collector_dir': '/tmp/results',
        'interface_args': ['--interface', '0-1@Ethernet1'],
        'test_params': {'thrift_server': '192.0.2.10'},
        'timeout_s': 60, 'env': {},
    }


def _session(tmp_path):
    return {
        'root': '/tmp/ranking/session',
        'container_id': 'a' * 64,
        'binding_root': '/binding',
    }


class Console:
    def __init__(self):
        self.finished = []

    def finish(self, *args):
        self.finished.append(args)


def _wire(monkeypatch, tmp_path, rc=0, cleanup_error=None):
    from tests.ranking.run import artifact_collection, case_executor, ptf_container

    console = Console()
    monkeypatch.setattr(case_executor, 'LiveConsole', lambda *args, **kwargs: console)
    monkeypatch.setattr(artifact_collection, 'create_run', lambda *args: None)
    monkeypatch.setattr(ptf_container, 'dispatch', lambda *args: None)
    monkeypatch.setattr(ptf_container, 'wait', lambda *args, **kwargs: (
        console, 0.5))

    def collect(host, session, run_id, staging):
        request = case_executor.ptf_protocol.build_request(
            _config(), session, CASE, session['root'] + '/runs/' + run_id)
        outcome = {
            'phase': 'ptf', 'argv': request['argv'], 'timeout_s': 60,
            'rc': rc, 'timed_out': False, 'process_exited': True,
            'container_id': 'a' * 64,
        }
        (staging / 'outcome.json').write_text(json.dumps(outcome))
        (staging / 'run.log').write_text(
            '===== PTF console output =====\n{}\n'
            '\n===== PTF internal log =====\n'.format('OK' if rc == 0 else 'FAILED'))
        if rc == 0:
            (staging / 'sairoute_multipleRoutesTest.json').write_text(json.dumps({
                'test_module': 'sairoute', 'test_class': 'multipleRoutesTest',
                'error_message': None,
                'metadata': {'platform': 'broadcom', 'port_count': 32},
                'spec_results': [{
                    'spec_name': 'ipv4_route_scale',
                    'operation': 'create',
                    'count': 100,
                    'actual_value': 100,
                    'unit': 'entries',
                    'baseline': None,
                    'result': 'PASS',
                    'result_type': 'scale',
                    'direction': 'higher_better',
                    'extra': {},
                }],
                'attr_records': [{
                    'case': CASE, 'attr': 'SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID',
                    'op': 'set', 'value': 'oid:0x1',
                }],
            }))
        return {entry.name: hashlib.sha256(entry.read_bytes()).hexdigest()
                for entry in staging.iterdir()}

    monkeypatch.setattr(artifact_collection, 'collect', collect)
    if cleanup_error:
        monkeypatch.setattr(
            artifact_collection, 'cleanup',
            lambda *args: (_ for _ in ()).throw(RuntimeError(cleanup_error)))
    else:
        monkeypatch.setattr(artifact_collection, 'cleanup', lambda *args: None)
    return console


def test_executor_publishes_passed_case_and_cleans_remote(monkeypatch, tmp_path):
    from tests.ranking.run.case_executor import execute

    console = _wire(monkeypatch, tmp_path)
    result = execute(object(), _config(), _session(tmp_path), CASE, tmp_path)
    assert set(result) == {'case', 'status', 'log_path'}
    assert result['status'] == 'passed'
    assert result['log_path'].is_file()
    assert result['log_path'] == (
        tmp_path / 'cases/sairoute/logs/multipleRoutesTest.log')
    merged = json.loads((
        tmp_path / 'cases/sairoute/results/multipleRoutesTest.json').read_text())
    assert merged['case'] == CASE
    assert merged['status'] == 'passed'
    assert merged['rc'] == 0
    assert merged['duration_seconds'] == 0.5
    assert merged['metadata'] == {'platform': 'broadcom'}
    assert merged['spec_results'][0]['count'] == 100
    assert merged['attr_records'][0]['case'] == CASE
    assert not (tmp_path / 'cases' / CASE).exists()
    assert console.finished[-1][0] == 'PASS'


def test_normal_ptf_failure_is_not_an_infrastructure_error(monkeypatch, tmp_path):
    from tests.ranking.run.case_executor import execute

    _wire(monkeypatch, tmp_path, rc=1)
    result = execute(object(), _config(), _session(tmp_path), CASE, tmp_path)
    assert result['status'] == 'failed'
    merged = json.loads((
        tmp_path / 'cases/sairoute/results/multipleRoutesTest.json').read_text())
    assert merged == {
        'case': CASE,
        'status': 'failed',
        'rc': 1,
        'duration_seconds': 0.5,
        'error_message': None,
        'metadata': {},
        'spec_results': [],
        'attr_records': [],
    }


def test_cleanup_failure_retains_published_case_and_stops_batch(monkeypatch, tmp_path):
    from tests.ranking.run.case_executor import InfrastructureError, execute

    _wire(monkeypatch, tmp_path, cleanup_error='remote delete failed')
    with pytest.raises(InfrastructureError, match='remote delete failed'):
        execute(object(), _config(), _session(tmp_path), CASE, tmp_path)
    assert (tmp_path / 'cases/sairoute/logs/multipleRoutesTest.log').is_file()


@pytest.mark.parametrize('failure_point', ('collect', 'verify'))
def test_collection_failure_cleans_remote_and_controller_staging(
        monkeypatch, tmp_path, failure_point):
    from tests.ranking.run import artifact_collection
    from tests.ranking.run.case_executor import InfrastructureError, execute

    _wire(monkeypatch, tmp_path)
    cleanup_calls = []
    monkeypatch.setattr(
        artifact_collection, 'cleanup',
        lambda *args: cleanup_calls.append(args))
    if failure_point == 'collect':
        def fail_collect(host, session, run_id, staging):
            (staging / 'run.log').write_text('partial evidence\n')
            raise RuntimeError('fetch failed')

        monkeypatch.setattr(artifact_collection, 'collect', fail_collect)
    else:
        monkeypatch.setattr(
            artifact_collection, 'verify',
            lambda *args: (_ for _ in ()).throw(ValueError('hash differs')))

    session = _session(tmp_path)
    with pytest.raises(InfrastructureError):
        execute(object(), _config(), session, CASE, tmp_path)

    assert len(cleanup_calls) == 1
    assert session == _session(tmp_path)
    assert list((tmp_path / 'cases').glob('.{}-*'.format(CASE))) == []
