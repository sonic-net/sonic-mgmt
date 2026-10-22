import base64
import json


class Host:
    def __init__(self):
        self.calls = []

    def command(self, *, argv, module_ignore_errors=True):
        self.calls.append(list(argv))
        if argv[:3] == ['docker', 'container', 'inspect']:
            return {'rc': 0, 'stdout': json.dumps([{
                'Name': '/saiserverv2', 'Id': 'a' * 64,
                'State': {'Running': True},
            }])}
        return {'rc': 0, 'stdout': ''}


def test_inspect_and_dispatch_pin_running_container():
    from tests.ranking.run import ptf_container

    host = Host()
    session = {'container_id': 'a' * 64,
               'runner_path': '/tmp/ranking/id/ptf_runner.py'}
    request = {'argv': ['ptf'], 'timeout_s': 1}
    ptf_container.dispatch(host, session, request)

    command = host.calls[-1]
    assert command[:4] == ['docker', 'exec', '-d', 'a' * 64]
    payload = command[command.index('--request-base64') + 1]
    assert json.loads(base64.b64decode(payload)) == request
    assert not any(call[:3] == ['docker', 'container', 'inspect']
                   for call in host.calls)


def test_wait_streams_poll_output_until_terminal(monkeypatch):
    from tests.ranking.run import artifact_collection, ptf_container

    values = iter([
        {'data': base64.b64encode(b'progress\n').decode(), 'offset': 38,
         'outcome': None},
        {'data': '', 'offset': 38,
         'outcome': {'process_exited': True, 'console_log_bytes': 38}},
    ])
    monkeypatch.setattr(
        artifact_collection, 'remote_operation', lambda *args, **kwargs: next(values))
    output = []
    _, duration = ptf_container.wait(
        object(), {}, 'a' * 32, {'timeout_s': 5}, 'sairoute.Case',
        mode='full', sink=output.append, sleeper=lambda _: None)
    assert duration >= 0
    assert any('progress' in item for item in output)
