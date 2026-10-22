import json


class Host:
    def __init__(self):
        self.calls = []

    def command(self, *, argv, module_ignore_errors=True, verbose=False):
        assert verbose is False
        self.calls.append(list(argv))
        if argv[:3] == ['docker', 'container', 'inspect']:
            return {'rc': 0, 'stdout': json.dumps([{
                'Name': '/saiserverv2', 'Id': 'a' * 64,
                'State': {'Running': True},
            }])}
        if 'RANKING_BINDING_PROBE' in ' '.join(argv):
            raise AssertionError('Run must leave binding loading to the case')
        return {'rc': 0, 'stdout': ''}


def _config(tmp_path):
    runner = tmp_path / 'ptf_runner.py'
    runner.write_text('print("runner")')
    return {
        'ptf_container': 'saiserverv2',
        'ptf_executable': '/SAI-TEST/test/ptf/ptf',
        'ptf_workdir': '/SAI-TEST', 'ptf_case_dir': '/SAI-TEST/ptf',
        'collector_dir': '/tmp/results', 'runner_path': str(runner),
        'env': {'PYTHONPATH': '/usr/lib/python3/dist-packages'},
    }


def test_session_validates_ready_runtime_and_injects_only_runner(tmp_path):
    from tests.ranking.run import ptf_container

    host = Host()
    value = ptf_container.open_session(host, _config(tmp_path))

    assert value['container_id'] == 'a' * 64
    assert set(value) == {
        'session_id', 'container_id', 'root', 'staging_base',
        'runner_path',
    }
    writes = [call for call in host.calls if 'RANKING_RUNNER_WRITE' in ' '.join(call)]
    assert len(writes) == 1
    assert not any('remote_artifacts.py' in ' '.join(call) for call in host.calls)


def test_session_creates_the_runtime_owned_collector_directory(tmp_path):
    from tests.ranking.run import ptf_container

    host = Host()
    ptf_container.open_session(host, _config(tmp_path))

    create = next(
        index for index, call in enumerate(host.calls)
        if 'RANKING_COLLECTOR_CREATE' in ' '.join(call))
    validate = next(
        index for index, call in enumerate(host.calls)
        if call[-3:] == ['test', '-d', '/tmp/results'])
    assert create < validate


def test_session_cleanup_targets_only_current_uuid_roots(tmp_path):
    from tests.ranking.run import ptf_container

    host = Host()
    value = ptf_container.open_session(host, _config(tmp_path))
    ptf_container.close_session(host, value)
    removals = [call for call in host.calls if 'RANKING_SESSION_REMOVE' in ' '.join(call)]
    assert len(removals) == 2
    assert all(value['session_id'] in call for call in removals)
    assert sum(call[:3] == ['docker', 'container', 'inspect']
               for call in host.calls) == 1
