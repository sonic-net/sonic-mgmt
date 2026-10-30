import json
import logging

import pytest

from tests.ranking import remote_agent
from tests.ranking.unit_tests.unit_test_state_store import RESOURCE, ENV, ledger, snapshot


@pytest.fixture(autouse=True)
def agent_roots(tmp_path, monkeypatch):
    monkeypatch.setattr(remote_agent, 'OWNERSHIP_ROOT', str(tmp_path / 'ownership'))
    monkeypatch.setattr(remote_agent, 'STATE_ROOT', str(tmp_path / 'state'))
    for handler in logging.getLogger().handlers:
        monkeypatch.setattr(handler, 'formatter', logging.Formatter('%(message)s'))


def invoke(tmp_path, capsys, request, success=True):
    path = tmp_path / 'request.json'
    path.write_text(json.dumps(request))
    code = remote_agent.main(['--request', str(path)])
    out, err = capsys.readouterr()
    if success:
        assert code == 0
        assert err == ''
        response = json.loads(out)
        assert set(response) == {'schema_version', 'action', 'result'}
        assert response['schema_version'] == 1
        assert response['action'] == request['action']
        assert len(out.splitlines()) == 1
        return response['result']
    assert code == 1
    assert out == ''
    assert len(err.splitlines()) == 1
    assert 'Traceback' not in err


def claim(tmp_path, capsys):
    result = invoke(tmp_path, capsys, dict(action='claim', resource=RESOURCE,
                                           environment_id=ENV, operation_id='op-a'))
    assert result == dict(resource=RESOURCE, environment_id=ENV,
                          operation_id='op-a', created=True)
    return result


def test_all_actions_with_controlled_results(tmp_path, capsys):
    handle = claim(tmp_path, capsys)
    record = invoke(tmp_path, capsys, dict(action='validate', handle=handle))
    assert record == dict(schema_version=1, resource=RESOURCE, environment_id=ENV,
                          operation_id='op-a', mutated=False, abortable=True)
    source = tmp_path / 'source'
    source.write_bytes(b'original')
    files = invoke(tmp_path, capsys, dict(action='capture_files', handle=handle,
                                          paths=[str(source)]))
    original = snapshot(files)
    assert invoke(tmp_path, capsys, dict(action='snapshot', handle=handle,
                                         identity=original['identity'],
                                         services=original['services'], paths=[str(source)],
                                         saiserver=original['saiserver'])) == original
    assert invoke(tmp_path, capsys, dict(action='write', handle=handle,
                                         name='ledger.json', value=ledger())) == {}
    assert invoke(tmp_path, capsys, dict(action='mark_attempt', handle=handle,
                                         marker='restore:' + str(source))) == {}
    source.write_bytes(b'changed')
    assert invoke(tmp_path, capsys, dict(action='restore_files', handle=handle,
                                         originals=files)) == {}
    assert source.read_bytes() == b'original'
    assert invoke(tmp_path, capsys, dict(action='complete_attempt', handle=handle,
                                         marker='restore:' + str(source))) == {}
    assert invoke(tmp_path, capsys, dict(action='read', handle=handle,
                                         name='ledger.json'))['completed'] == ['restore:' + str(source)]
    assert invoke(tmp_path, capsys, dict(action='keep', handle=handle)) == {}
    resumed = invoke(tmp_path, capsys, dict(action='resume', resource=RESOURCE,
                                            environment_id=ENV, operation_id='op-b'))
    assert resumed == dict(handle, operation_id='op-b', created=False)
    assert invoke(tmp_path, capsys, dict(action='release', handle=resumed)) == {}
    handle = claim(tmp_path, capsys)
    assert invoke(tmp_path, capsys, dict(action='abort', handle=handle)) == {}


@pytest.mark.parametrize('payload', [
    {}, [], None, {'action': 'exec', 'command': 'anything'},
    {'action': 'claim', 'root': '/arbitrary', 'resource': RESOURCE,
     'environment_id': ENV, 'operation_id': 'op-a'},
    {'action': 'collect', 'handle': {}}, {'action': 'block_snapshot', 'handle': {}},
])
def test_unknown_requests_fail_one_line(tmp_path, capsys, payload):
    invoke(tmp_path, capsys, payload, success=False)


@pytest.mark.parametrize('action', ['claim', 'resume', 'keep', 'abort', 'release',
                                    'validate', 'read', 'write', 'capture_files',
                                    'restore_files', 'mark_attempt', 'complete_attempt',
                                    'snapshot'])
def test_each_action_rejects_extra_fields_before_state_access(tmp_path, capsys, monkeypatch, action):
    def forbidden(*args, **kwargs):
        raise AssertionError('dispatch before request validation')
    monkeypatch.setattr(remote_agent, 'StateStore', forbidden)
    invoke(tmp_path, capsys, dict(action=action, root='/anything'), success=False)


@pytest.mark.parametrize('raw', ['[]', 'null', '{"action":"claim","action":"resume"}',
                                 '{"action":NaN}', '{"action":Infinity}', '{'])
def test_strict_request_json(tmp_path, capsys, raw):
    path = tmp_path / 'request.json'
    path.write_text(raw)
    assert remote_agent.main(['--request', str(path)]) == 1
    out, err = capsys.readouterr()
    assert out == ''
    assert len(err.splitlines()) == 1
    assert 'Traceback' not in err


def test_snapshot_resume_does_not_recapture_original(tmp_path, capsys, monkeypatch):
    handle = claim(tmp_path, capsys)
    source = tmp_path / 'source'
    source.write_text('original')
    value = snapshot()
    payload = dict(action='snapshot', handle=handle, identity=value['identity'],
                   services=value['services'], paths=[str(source)], saiserver=value['saiserver'])
    original = invoke(tmp_path, capsys, payload)
    invoke(tmp_path, capsys, dict(action='keep', handle=handle))
    resumed = invoke(tmp_path, capsys, dict(action='resume', resource=RESOURCE,
                                            environment_id=ENV, operation_id='op-b'))
    source.write_text('changed')

    def forbidden(*args, **kwargs):
        raise AssertionError('original recaptured')
    monkeypatch.setattr(remote_agent.StateStore, '_capture_files', forbidden)
    assert invoke(tmp_path, capsys, dict(payload, handle=resumed)) == original
    changed = dict(payload, handle=resumed,
                   services=dict(value['services'], swss='inactive'))
    invoke(tmp_path, capsys, changed, success=False)


@pytest.mark.parametrize('action', ['read', 'write', 'capture_files', 'restore_files',
                                    'mark_attempt', 'complete_attempt', 'snapshot'])
@pytest.mark.parametrize('wrong', ['environment', 'stale'])
def test_agent_wrong_handle_before_environment_access(tmp_path, capsys, monkeypatch, action, wrong):
    handle = claim(tmp_path, capsys)
    if wrong == 'environment':
        bad = dict(handle, environment_id='other')
    else:
        invoke(tmp_path, capsys, dict(action='keep', handle=handle))
        invoke(tmp_path, capsys, dict(action='resume', resource=RESOURCE,
                                      environment_id=ENV, operation_id='op-b'))
        bad = handle
    value = snapshot()

    def forbidden(*args, **kwargs):
        raise AssertionError('unauthorized environment access')
    monkeypatch.setattr(remote_agent.StateStore, '_open_environment', forbidden)
    fields = {
        'read': dict(name='snapshot.json'), 'write': dict(name='ledger.json', value=ledger()),
        'capture_files': dict(paths=[]), 'restore_files': dict(originals={}),
        'mark_attempt': dict(marker='start:saiserver'), 'complete_attempt': dict(marker='start:saiserver'),
        'snapshot': dict(identity=dict(value['identity'], environment_id=bad['environment_id']),
                         services=value['services'], paths=[], saiserver=value['saiserver']),
    }
    invoke(tmp_path, capsys, dict(action=action, handle=bad, **fields[action]), success=False)


def test_cli_storage_error_is_one_line_with_no_trace(tmp_path, capsys, monkeypatch):
    handle = claim(tmp_path, capsys)
    logger = logging.getLogger('tests.ranking.state_store')
    import sys
    handler = logging.StreamHandler(sys.stderr)
    monkeypatch.setattr(logger, 'handlers', [handler])
    invoke(tmp_path, capsys, dict(action='read', handle=handle, name='snapshot.json'), success=False)


@pytest.mark.parametrize('argv', [[], ['--help'], ['--request'],
                                  ['--request', '/nonexistent/request.json'],
                                  ['--request', '/nonexistent/request.json', '--root', '/arbitrary']])
def test_cli_parser_and_missing_request_fail_cleanly(capsys, argv):
    assert remote_agent.main(argv) == 1
    out, err = capsys.readouterr()
    assert out == ''
    assert len(err.splitlines()) == 1
    assert 'Traceback' not in err


@pytest.mark.parametrize('kind', ['fifo', 'symlink', 'hardlink'])
def test_request_file_is_not_followed_or_blocked(tmp_path, capsys, kind):
    import os
    path = tmp_path / 'request.json'
    if kind == 'fifo':
        os.mkfifo(path)
        from unittest.mock import patch
        with patch('builtins.open', side_effect=AssertionError('blocking request open')):
            assert remote_agent.main(['--request', str(path)]) == 1
    else:
        source = tmp_path / 'source'
        source.write_text(json.dumps(dict(action='claim', resource=RESOURCE,
                                          environment_id=ENV, operation_id='op-a')))
        if kind == 'symlink':
            path.symlink_to(source)
        else:
            os.link(source, path)
        assert remote_agent.main(['--request', str(path)]) == 1
    out, err = capsys.readouterr()
    assert out == ''
    assert len(err.splitlines()) == 1


def test_same_operation_cannot_start_recovery_during_an_owned_action(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(remote_agent, 'ACTION_ROOT', str(tmp_path.resolve() / 'actions'), raising=False)
    handle = claim(tmp_path, capsys)
    guard = invoke(tmp_path, capsys, dict(action='begin_action', handle=handle, action_id='action-run'))
    invoke(tmp_path, capsys, dict(action='begin_action', handle=handle, action_id='action-recovery'), success=False)
    invoke(tmp_path, capsys, dict(action='end_action', handle=guard))
    recovered = invoke(tmp_path, capsys, dict(action='begin_action', handle=handle, action_id='action-recovery'))
    assert recovered['operation_id'] == 'action-recovery'


def test_action_guard_survives_main_reservation_release(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(remote_agent, 'ACTION_ROOT', str(tmp_path.resolve() / 'actions'), raising=False)
    handle = claim(tmp_path, capsys)
    guard = invoke(tmp_path, capsys, dict(action='begin_action', handle=handle, action_id='action-old'))
    invoke(tmp_path, capsys, dict(action='release', handle=handle))
    fresh = claim(tmp_path, capsys)
    invoke(tmp_path, capsys, dict(action='begin_action', handle=fresh, action_id='action-new'), success=False)
    invoke(tmp_path, capsys, dict(action='end_action', handle=guard))
    invoke(tmp_path, capsys, dict(action='begin_action', handle=fresh, action_id='action-new'))
