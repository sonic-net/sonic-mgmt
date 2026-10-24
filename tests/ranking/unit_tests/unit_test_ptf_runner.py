import errno
import json
import os
import signal
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import pytest

from tests.ranking import ptf_runner


requires_linux_proc = pytest.mark.skipif(
    sys.platform != 'linux', reason='Live process identity requires Linux /proc')


def _stat(pid, *, group=None, session=None, birth='birth-a', state='S', threads=1):
    fields = ['0'] * 20
    fields[0] = state
    fields[1] = '1'
    fields[2] = str(pid if group is None else group)
    fields[3] = str(pid if session is None else session)
    fields[17] = str(threads)
    fields[19] = birth
    return '{} (python3) {}'.format(pid, ' '.join(fields))


class _Session:
    def __init__(self, pid, birth='birth-a', exit_signal=signal.SIGTERM):
        self.records = {pid: _stat(pid, birth=birth)}
        self.now = 0.0
        self.exit_signal = exit_signal
        self.kill = Mock(side_effect=self._kill)

    def _kill(self, group, sig):
        if sig == self.exit_signal:
            self.records = {pid: text for pid, text in self.records.items()
                            if int(ptf_runner._parse_stat(text)[2]) != group}

    def scan(self):
        return list(self.records.items())

    def pause(self, seconds):
        self.now += seconds

    def options(self):
        return {'proc_scanner': self.scan, 'group_kill': self.kill,
                'clock': lambda: self.now, 'sleeper': self.pause}


@pytest.mark.parametrize('failed_write', [1, 2])
def test_outcome_write_failure_still_cleans_owned_session(tmp_path, failed_write):
    process = Mock(pid=4321, returncode=-signal.SIGTERM)
    process.wait.side_effect = ([-signal.SIGTERM] if failed_write == 1 else
                                [subprocess.TimeoutExpired(['ptf'], 1), -signal.SIGTERM])
    write_outcome = ptf_runner._write_outcome
    writes = []

    def persist(path, outcome):
        writes.append(dict(outcome))
        if len(writes) == failed_write:
            raise OSError(errno.ENOSPC, 'No space left on device')
        write_outcome(path, outcome)

    with patch.object(ptf_runner.subprocess, 'Popen', return_value=process), \
            patch.object(ptf_runner, 'process_birth', return_value='birth-a'), \
            patch.object(ptf_runner, '_write_outcome', side_effect=persist), \
            patch.object(ptf_runner, '_cleanup_session') as cleanup:
        outcome = ptf_runner.run_ptf(
            ['ptf'], env={}, cwd=str(tmp_path),
            run_dir=str(tmp_path / 'run'), timeout_s=1)
    cleanup.assert_called_once()
    assert cleanup.call_args.args == (4321, 'birth-a')
    assert outcome['process_exited'] is True
    assert 'No space left on device' in outcome['error']
    assert outcome['rc'] == (-signal.SIGTERM if failed_write == 1 else 124)
    assert ptf_runner.load_outcome(tmp_path / 'run' / 'outcome.json') == outcome


def test_proc_scan_ignores_process_reaped_between_open_and_read():
    entries = MagicMock()
    entries.__enter__.return_value = iter([
        SimpleNamespace(name='self'), SimpleNamespace(name='4321'),
        SimpleNamespace(name='4322'),
    ])
    with patch.object(ptf_runner.os, 'scandir', return_value=entries), \
            patch.object(ptf_runner, '_proc_stat', side_effect=[
                ProcessLookupError(errno.ESRCH, 'No such process'), STAT_TEXT]):
        assert ptf_runner._proc_scan() == [(4322, STAT_TEXT)]


def test_timeout_terminates_only_owned_group(tmp_path):
    session = _Session(4321)
    process = Mock(pid=4321, returncode=-signal.SIGTERM)
    process.wait.side_effect = [subprocess.TimeoutExpired(['ptf'], 1),
                                -signal.SIGTERM]
    with patch.object(ptf_runner.subprocess, 'Popen', return_value=process) as launch, \
            patch.object(ptf_runner, 'process_birth', return_value='birth-a'):
        result = ptf_runner.run_ptf(['ptf', 'sairoute.RouteA'], env={},
                                    cwd=str(tmp_path),
                                    run_dir=str(tmp_path / 'run'), timeout_s=1,
                                    **session.options())
    assert launch.call_args.kwargs['start_new_session'] is True
    assert launch.call_args.kwargs['shell'] is False
    session.kill.assert_called_once_with(4321, signal.SIGTERM)
    assert result['rc'] == 124 and result['timed_out'] is True
    assert json.loads((tmp_path / 'run' / 'outcome.json').read_text()) == result


def test_collection_error_does_not_replace_primary_error():
    primary = {'rc': 23, 'phase': 'prepare_case', 'error': 'reset failed'}
    result = ptf_runner.merge_outcome(primary, ['fetch failed'])
    assert result['rc'] == 23 and result['error'] == 'reset failed'
    assert result['collection_errors'] == ['fetch failed']
    assert result['collected'] is False


def test_merge_outcome_returns_a_copy_and_never_rewrites_primary():
    primary = {'rc': 0, 'phase': 'ptf', 'collected': True,
               'collection_errors': ['stale']}
    result = ptf_runner.merge_outcome(primary, [])
    assert result == {'rc': 0, 'phase': 'ptf', 'collection_errors': [],
                      'collected': False}
    assert primary == {'rc': 0, 'phase': 'ptf', 'collected': True,
                       'collection_errors': ['stale']}
    with pytest.raises(ValueError):
        ptf_runner.merge_outcome(['not', 'a', 'dict'], [])
    with pytest.raises(ValueError):
        ptf_runner.merge_outcome(primary, 'fetch failed')


def test_term_ignored_escalates_to_group_kill(tmp_path):
    session = _Session(5150, birth='birth-b', exit_signal=signal.SIGKILL)
    process = Mock(pid=5150, returncode=-signal.SIGKILL)
    process.wait.side_effect = [subprocess.TimeoutExpired(['ptf'], 1),
                                -signal.SIGKILL]
    with patch.object(ptf_runner.subprocess, 'Popen', return_value=process), \
            patch.object(ptf_runner, 'process_birth', return_value='birth-b'):
        result = ptf_runner.run_ptf(['ptf'], env={}, cwd=str(tmp_path),
                                    run_dir=str(tmp_path / 'run'), timeout_s=1,
                                    **session.options())
    assert list(dict.fromkeys(call.args for call in session.kill.call_args_list)) == [
        (5150, signal.SIGTERM), (5150, signal.SIGKILL)]
    assert session.now >= ptf_runner.GRACE_SECONDS
    assert result['rc'] == 124 and result['timed_out'] is True
    assert result['process_exited'] is True


def test_recycled_pid_birth_change_never_signaled(tmp_path):
    session = _Session(6161, birth='birth-z')
    process = Mock(pid=6161, returncode=0)
    process.wait.side_effect = [subprocess.TimeoutExpired(['ptf'], 1), 0]
    with patch.object(ptf_runner.subprocess, 'Popen', return_value=process), \
        patch.object(ptf_runner, 'process_birth',
                     return_value='birth-a'):
        result = ptf_runner.run_ptf(['ptf'], env={}, cwd=str(tmp_path),
                                    run_dir=str(tmp_path / 'run'), timeout_s=1,
                                    **session.options())
    session.kill.assert_not_called()
    assert result['rc'] == 124 and result['timed_out'] is True
    assert result['process_exited'] is False
    assert 'identity or session is lost or mismatched' in result['error']


def test_unproven_exit_records_process_not_exited(tmp_path):
    session = _Session(7171, birth='birth-c', exit_signal=None)
    process = Mock(pid=7171, returncode=None)
    process.wait.side_effect = subprocess.TimeoutExpired(['ptf'], 1)
    process.poll.return_value = None
    with patch.object(ptf_runner.subprocess, 'Popen', return_value=process), \
            patch.object(ptf_runner, 'process_birth', return_value='birth-c'):
        result = ptf_runner.run_ptf(['ptf'], env={}, cwd=str(tmp_path),
                                    run_dir=str(tmp_path / 'run'), timeout_s=1,
                                    **session.options())
    assert result['rc'] == 124 and result['timed_out'] is True
    assert result['process_exited'] is False


def test_spawn_failure_returns_outcome_without_raising(tmp_path):
    error = FileNotFoundError('No such file or directory: missing-ptf-bin')
    with patch.object(ptf_runner.subprocess, 'Popen', side_effect=error):
        result = ptf_runner.run_ptf(['/missing-ptf-bin'], env={},
                                    cwd=str(tmp_path),
                                    run_dir=str(tmp_path / 'run'), timeout_s=5)
    assert result['rc'] != 0
    assert result['timed_out'] is False
    assert result['process_exited'] is True
    assert result['pid'] is None
    assert 'No such file or directory: missing-ptf-bin' in result['error']
    assert json.loads((tmp_path / 'run' / 'outcome.json').read_text()) == result


def test_run_ptf_refuses_existing_run_dir(tmp_path):
    run = tmp_path / 'run'
    run.mkdir()
    with pytest.raises(FileExistsError):
        ptf_runner.run_ptf([sys.executable, '-c', 'pass'], env={},
                           cwd=str(tmp_path), run_dir=str(run), timeout_s=5)


@requires_linux_proc
def test_real_child_success_lands_logs_and_outcome(tmp_path):
    cwd = tmp_path / 'cwd'
    cwd.mkdir()
    result = ptf_runner.run_ptf(
        [sys.executable, '-c', 'print("ranked-out")\nimport sys\n'
         'sys.stderr.write("ranked-err\\n")'],
        env=dict(os.environ), cwd=str(cwd), run_dir=str(tmp_path / 'run'),
        timeout_s=60)
    assert result['rc'] == 0
    assert result['timed_out'] is False
    assert result['process_exited'] is True
    assert result['phase'] == 'ptf'
    assert result['argv'][0] == sys.executable
    assert (tmp_path / 'run' / 'stdout.log').read_text().strip() == 'ranked-out'
    assert 'ranked-err' in (tmp_path / 'run' / 'stderr.log').read_text()
    assert json.loads(
        (tmp_path / 'run' / 'outcome.json').read_text()) == result


@requires_linux_proc
def test_real_child_failure_rc_is_observed(tmp_path):
    cwd = tmp_path / 'cwd'
    cwd.mkdir()
    result = ptf_runner.run_ptf(
        [sys.executable, '-c', 'import sys; sys.exit(7)'],
        env=dict(os.environ), cwd=str(cwd), run_dir=str(tmp_path / 'run'),
        timeout_s=60)
    assert result['rc'] == 7
    assert result['timed_out'] is False
    assert result['process_exited'] is True
    assert json.loads(
        (tmp_path / 'run' / 'outcome.json').read_text()) == result


@requires_linux_proc
def test_real_child_timeout_terminates_owned_group(tmp_path):
    cwd = tmp_path / 'cwd'
    cwd.mkdir()
    real_killpg = os.killpg
    with patch.object(ptf_runner.os, 'killpg', side_effect=real_killpg) as kill:
        result = ptf_runner.run_ptf(
            [sys.executable, '-c', 'import time; time.sleep(60)'],
            env=dict(os.environ), cwd=str(cwd), run_dir=str(tmp_path / 'run'),
            timeout_s=1)
    assert result['timed_out'] is True
    assert result['rc'] == 124
    assert result['process_exited'] is True
    assert isinstance(result['birth'], str) and result['birth']
    assert (result['pid'], signal.SIGTERM) in [call.args for call in kill.call_args_list]
    assert json.loads(
        (tmp_path / 'run' / 'outcome.json').read_text()) == result


STAT_TEXT = ('4321 (python3) S 1 4321 4321 0 -1 4194304 0 0 0 0 1 0 0 0 '
             '20 0 3 0 123456789')


def test_process_birth_reads_starttime_and_requires_group_leader():
    assert ptf_runner.process_birth(4321, reader=lambda pid: STAT_TEXT) == '123456789'
    other_group = STAT_TEXT.replace(') S 1 4321 4321', ') S 1 99 99', 1)
    assert ptf_runner.process_birth(4321, reader=lambda pid: other_group) is None


def test_process_birth_handles_parenthesised_comm_and_malformed_stat():
    parenthesised = STAT_TEXT.replace('(python3)', '(py (thon))')
    assert ptf_runner.process_birth(4321, reader=lambda pid: parenthesised) == '123456789'
    for text in ('', 'garbage', '1 () S 1 1 1', ' '.join(STAT_TEXT.split()[:-2])):
        assert ptf_runner.process_birth(4321, reader=lambda pid, t=text: t) is None


def test_process_birth_unreadable_or_invalid_pid_returns_none():
    def missing(pid):
        raise FileNotFoundError('/proc/{0}/stat'.format(pid))

    assert ptf_runner.process_birth(99, reader=missing) is None
    assert ptf_runner.process_birth(99, reader=lambda pid: None) is None
    assert ptf_runner.process_birth(0, reader=lambda pid: STAT_TEXT) is None
    assert ptf_runner.process_birth(-1, reader=lambda pid: STAT_TEXT) is None
    assert ptf_runner.process_birth('4321', reader=lambda pid: STAT_TEXT) is None


def _request(tmp_path, **overrides):
    request = {
        'argv': [sys.executable, '-c', 'print("main-done")'],
        'env': dict(os.environ),
        'cwd': str(tmp_path),
        'run_dir': str(tmp_path / 'runs' / 'run-a'),
        'timeout_s': 60,
    }
    request.update(overrides)
    path = tmp_path / 'request.json'
    path.write_text(json.dumps(request))
    return path


@requires_linux_proc
def test_main_runs_request_and_prints_outcome(tmp_path, capsys):
    code = ptf_runner.main(['--request', str(_request(tmp_path))])
    outcome = json.loads(capsys.readouterr().out)
    assert code == 0
    assert outcome['rc'] == 0 and outcome['process_exited'] is True
    assert json.loads(
        (tmp_path / 'runs' / 'run-a' / 'outcome.json').read_text()) == outcome
    assert (tmp_path / 'runs' / 'run-a' / 'stdout.log').read_text().strip() == \
        'main-done'


@requires_linux_proc
def test_main_exit_code_reflects_request_outcome_rc(tmp_path, capsys):
    request = _request(tmp_path, argv=[sys.executable, '-c', 'import sys; sys.exit(7)'])
    code = ptf_runner.main(['--request', str(request)])
    outcome = json.loads(capsys.readouterr().out)
    assert code == 7
    assert outcome['rc'] == 7


def test_main_refuses_existing_run_dir(tmp_path, capsys):
    run = tmp_path / 'runs' / 'run-a'
    run.mkdir(parents=True)
    (run / 'sentinel').write_text('kept')
    code = ptf_runner.main(['--request', str(_request(tmp_path))])
    assert code == 1
    assert 'ptf_runner' in capsys.readouterr().err
    assert (run / 'sentinel').read_text() == 'kept'


@pytest.mark.parametrize('text', ['{not json', '[]', 'null',
                                  '{"argv": "ptf"}'])
def test_main_rejects_malformed_request_json(tmp_path, capsys, text):
    path = tmp_path / 'request.json'
    path.write_text(text)
    assert ptf_runner.main(['--request', str(path)]) == 1
    assert 'ptf_runner' in capsys.readouterr().err


@pytest.mark.parametrize('mutation', [
    lambda request: request.pop('run_dir'),
    lambda request: request.update(timeout_s=0),
    lambda request: request.update(timeout_s='60'),
    lambda request: request.update(argv=[]),
    lambda request: request.update(argv=['ptf', 7]),
    lambda request: request.update(env={'PYTHONPATH': None}),
    lambda request: request.update(env='PATH=/bin'),
    lambda request: request.update(cwd=''),
])
def test_main_rejects_invalid_request_shapes(tmp_path, capsys, mutation):
    request = {
        'argv': [sys.executable, '-c', 'pass'], 'env': {},
        'cwd': str(tmp_path), 'run_dir': str(tmp_path / 'runs' / 'run-a'),
        'timeout_s': 5,
    }
    mutation(request)
    path = tmp_path / 'request.json'
    path.write_text(json.dumps(request))
    assert ptf_runner.main(['--request', str(path)]) == 1
    assert 'ptf_runner' in capsys.readouterr().err


def test_main_rejects_duplicate_request_keys(tmp_path, capsys):
    path = tmp_path / 'request.json'
    path.write_text('{"argv": ["a"], "argv": ["b"]}')
    assert ptf_runner.main(['--request', str(path)]) == 1
    assert 'ptf_runner' in capsys.readouterr().err


def test_main_rejects_missing_request_and_bad_usage(tmp_path, capsys):
    assert ptf_runner.main(['--request', str(tmp_path / 'missing.json')]) == 1
    assert ptf_runner.main([]) == 1
    assert ptf_runner.main(['--request']) == 1
    assert ptf_runner.main(['--request', 'a', 'b']) == 1
    assert ptf_runner.main(['--verbose', 'x']) == 1
    assert 'ptf_runner' in capsys.readouterr().err


def test_persistent_outcome_write_failure_cleans_before_raising(tmp_path):
    process = Mock(pid=4321, returncode=-signal.SIGTERM)
    process.wait.return_value = -signal.SIGTERM
    with patch.object(ptf_runner.subprocess, 'Popen', return_value=process), \
            patch.object(ptf_runner, 'process_birth', return_value='birth-a'), \
            patch.object(ptf_runner, '_write_outcome', side_effect=OSError(errno.ENOSPC, 'disk full')), \
            patch.object(ptf_runner, '_cleanup_session') as cleanup:
        with pytest.raises(OSError, match='disk full'):
            ptf_runner.run_ptf(['ptf'], env={}, cwd=str(tmp_path),
                               run_dir=str(tmp_path / 'run'), timeout_s=1)
    cleanup.assert_called_once()
    process.wait.assert_called_once_with(timeout=ptf_runner.GRACE_SECONDS)


def test_proc_scan_does_not_ignore_permission_failure():
    entries = MagicMock()
    entries.__enter__.return_value = iter([SimpleNamespace(name='4321')])
    with patch.object(ptf_runner.os, 'scandir', return_value=entries), \
            patch.object(ptf_runner, '_proc_stat', side_effect=PermissionError('denied')):
        with pytest.raises(PermissionError, match='denied'):
            ptf_runner._proc_scan()


def test_wait_error_still_cleans_the_session(tmp_path):
    process = Mock(pid=4321, returncode=-signal.SIGTERM)
    process.wait.side_effect = [OSError(errno.ECHILD, 'wait failed'), -signal.SIGTERM]
    session = _Session(4321)
    with patch.object(ptf_runner.subprocess, 'Popen', return_value=process), \
            patch.object(ptf_runner, 'process_birth', return_value='birth-a'):
        outcome = ptf_runner.run_ptf(['ptf'], env={}, cwd=str(tmp_path),
                                     run_dir=str(tmp_path / 'run'), timeout_s=1,
                                     **session.options())
    session.kill.assert_called_once_with(4321, signal.SIGTERM)
    assert outcome['process_exited'] is True
    assert outcome['rc'] == -signal.SIGTERM
    assert 'could not wait for PTF' in outcome['error']


def test_cleanup_covers_descendant_groups_after_session_leader_exits():
    session = _Session(4321)
    session.records = {
        4322: _stat(4322, group=4322, session=4321),
        4323: _stat(4323, group=4323, session=4321),
        9876: _stat(9876),
    }
    ptf_runner._cleanup_session(4321, 'birth-a', **session.options())
    assert [call.args for call in session.kill.call_args_list] == [
        (4322, signal.SIGTERM), (4323, signal.SIGTERM)]
    assert list(session.records) == [9876]


def test_cleanup_follows_a_descendant_that_changes_group():
    session = _Session(4321)
    session.records = {4322: _stat(4322, group=4321, session=4321)}
    scans = []

    def scan():
        scans.append(True)
        if len(scans) == 2:
            session.records[4322] = _stat(4322, group=4322, session=4321)
        return session.scan()

    options = dict(session.options(), proc_scanner=scan)
    ptf_runner._cleanup_session(4321, 'birth-a', **options)
    session.kill.assert_called_once_with(4322, signal.SIGTERM)


def test_cleanup_refuses_changed_signal_target_identity():
    scanner = Mock(side_effect=[
        [(4322, _stat(4322, group=4321, session=4321, birth='old'))],
        [(4322, _stat(4322, group=4321, session=4321, birth='new'))],
    ])
    kill = Mock()
    with pytest.raises(ValueError, match='identity changed before killpg'):
        ptf_runner._cleanup_session(4321, 'birth-a', proc_scanner=scanner,
                                    group_kill=kill)
    kill.assert_not_called()


@pytest.mark.parametrize('threads, expected_members', [(1, 0), (2, 1)])
def test_zombie_session_leader_counts_only_if_threads_are_live(threads, expected_members):
    records = [(4321, _stat(4321, state='Z', threads=threads))]
    assert len(ptf_runner._session_members(4321, 'birth-a', lambda: records)) == expected_members


def test_cleanup_refuses_a_conflicting_session():
    records = [(4322, _stat(4322, group=4321, session=9876))]
    kill = Mock()
    with pytest.raises(ValueError, match='conflicting session'):
        ptf_runner._cleanup_session(4321, 'birth-a', proc_scanner=lambda: records,
                                    group_kill=kill)
    kill.assert_not_called()


def _outcome(**overrides):
    value = {
        'phase': 'ptf', 'pid': 4321, 'group': 4321, 'birth': 'birth-a',
        'argv': ['ptf', 'saisanity.Case'], 'timeout_s': 1, 'rc': 124,
        'timed_out': True, 'process_exited': False,
    }
    value.update(overrides)
    return value


def test_recover_outcome_preserves_primary_timeout_and_rewrites_exit_proof(tmp_path):
    path = tmp_path / 'outcome.json'
    path.write_text(json.dumps(_outcome()))
    session = _Session(4321)
    recovered = ptf_runner.recover_outcome(path, **session.options())
    session.kill.assert_called_once_with(4321, signal.SIGTERM)
    assert recovered['process_exited'] is True
    assert recovered['rc'] == 124 and recovered['timed_out'] is True
    assert ptf_runner.load_outcome(path) == recovered


def test_recover_without_exit_status_records_an_error(tmp_path):
    path = tmp_path / 'outcome.json'
    path.write_text(json.dumps(_outcome(rc=None, timed_out=False)))
    recovered = ptf_runner.recover_outcome(path, proc_scanner=lambda: [])
    assert recovered['process_exited'] is True and recovered['rc'] == 1
    assert 'exit status is unavailable' in recovered['error']


def test_recover_refuses_reused_pid_without_rewriting_original(tmp_path):
    original = json.dumps(_outcome())
    path = tmp_path / 'outcome.json'
    path.write_text(original)
    session = _Session(4321, birth='new-birth')
    with pytest.raises(ValueError, match='identity or session is lost or mismatched'):
        ptf_runner.recover_outcome(path, **session.options())
    session.kill.assert_not_called()
    assert path.read_text() == original


@pytest.mark.parametrize('changes', [
    {'pid': True}, {'group': 1234}, {'birth': None, 'process_exited': True},
    {'process_exited': 1}, {'rc': None, 'process_exited': True},
    {'container_id': 'ptf-name'}, {'error': ''}, {'unknown': True},
])
def test_invalid_outcome_cannot_supply_exit_proof(changes):
    with pytest.raises(ValueError):
        ptf_runner.parse_outcome(json.dumps(_outcome(**changes)))


def test_docker_dispatch_request_preserves_literal_case_arguments(tmp_path):
    container_id = 'a' * 64
    parameters = 'name="semi;colon",enabled=True,count=3'
    arguments = ['ptf', '--test-params', parameters]
    request = {
        'argv': ['/usr/bin/docker', 'exec', '--env', 'PLATFORM=common',
                 container_id] + arguments,
        'env': {}, 'cwd': str(tmp_path), 'run_dir': str(tmp_path / 'run'),
        'timeout_s': 1,
    }
    inner = ptf_runner._docker_request(request)
    assert inner['argv'] == arguments
    assert inner['env'] == {'PLATFORM': 'common'}
    assert inner['container_id'] == container_id
    assert request['argv'][-1] == parameters and request['env'] == {}


def _container_copier(outcome):
    def copy(container_id, source, run_path, name):
        temporary = run_path / ('.copied-' + name)
        temporary.write_text(json.dumps(outcome) if name == 'outcome.json' else name)
        return temporary
    return copy


def test_dispatch_starts_inner_runner_and_collects_its_actual_outcome(tmp_path):
    container_id = 'a' * 64
    request = {
        'argv': ['ptf', 'saisanity.Case'], 'env': {'PLATFORM': 'common'},
        'cwd': str(tmp_path), 'run_dir': str(tmp_path / 'run'),
        'timeout_s': 1, 'container_id': container_id,
    }
    expected = _outcome(container_id=container_id, rc=0, timed_out=False, process_exited=True)
    with patch.object(ptf_runner.subprocess, 'run', return_value=subprocess.CompletedProcess(
            [], 0, stdout='', stderr='')) as execute, \
            patch.object(ptf_runner, '_copy_container_file', side_effect=_container_copier(expected)):
        actual = ptf_runner.dispatch_container(request)
    assert actual == expected
    assert execute.call_args.args[0] == [
        'docker', 'exec', '-i', container_id, 'python3',
        ptf_runner._runner_path(), '--request', '-']
    assert json.loads(execute.call_args.kwargs['input']) == request
    assert ptf_runner.load_outcome(tmp_path / 'run' / 'outcome.json') == expected
    assert (tmp_path / 'run' / 'stdout.log').read_text() == 'stdout.log'


def test_dispatch_cannot_claim_exit_from_another_container(tmp_path):
    request = {
        'argv': ['ptf', 'saisanity.Case'], 'env': {}, 'cwd': str(tmp_path),
        'run_dir': str(tmp_path / 'run'), 'timeout_s': 1, 'container_id': 'a' * 64,
    }
    wrong = _outcome(container_id='b' * 64, process_exited=True)
    with patch.object(ptf_runner.subprocess, 'run', return_value=subprocess.CompletedProcess(
            [], 0, stdout='', stderr='')), \
            patch.object(ptf_runner, '_copy_container_file', side_effect=_container_copier(wrong)):
        actual = ptf_runner.dispatch_container(request)
    assert actual['process_exited'] is False and actual['pid'] is None
    assert 'differs from dispatch provenance' in actual['error']


def test_unconfirmed_container_dispatch_does_not_supply_exit_proof(tmp_path):
    request = {
        'argv': ['ptf', 'saisanity.Case'], 'env': {}, 'cwd': str(tmp_path),
        'run_dir': str(tmp_path / 'run'), 'timeout_s': 1, 'container_id': 'a' * 64,
    }
    with patch.object(ptf_runner.subprocess, 'run', side_effect=subprocess.TimeoutExpired(
            ['docker', 'exec'], 21)), \
            patch.object(ptf_runner, '_copy_container_file', side_effect=ValueError('unavailable')):
        actual = ptf_runner.dispatch_container(request)
    assert actual['pid'] is None and actual['rc'] is None
    assert actual['process_exited'] is False
    assert 'container dispatch is unconfirmed' in actual['error']
    assert ptf_runner.load_outcome(tmp_path / 'run' / 'outcome.json') == actual


def test_container_recovery_reloads_logs_after_the_actual_session_exits(tmp_path):
    original = _outcome(container_id='a' * 64)
    path = tmp_path / 'outcome.json'
    path.write_text(json.dumps(original))
    recovered = dict(original, process_exited=True)
    with patch.object(ptf_runner.subprocess, 'run', return_value=subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(recovered), stderr='')) as execute, \
            patch.object(ptf_runner, '_copy_container_file',
                         side_effect=_container_copier(recovered)) as copy:
        actual = ptf_runner.recover_host_outcome(path)
    assert actual == recovered and ptf_runner.load_outcome(path) == recovered
    assert execute.call_args.args[0] == [
        'docker', 'exec', original['container_id'], 'python3', ptf_runner._runner_path(),
        '--recover-local-outcome', str(path)]
    assert [call.args[-1] for call in copy.call_args_list] == ['stdout.log', 'stderr.log']
    assert (tmp_path / 'stdout.log').read_text() == 'stdout.log'


def test_container_recovery_rejects_changed_identity_before_copying_logs(tmp_path):
    original = _outcome(container_id='a' * 64)
    path = tmp_path / 'outcome.json'
    path.write_text(json.dumps(original))
    recovered = dict(original, process_exited=True, birth='new-birth')
    with patch.object(ptf_runner.subprocess, 'run', return_value=subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(recovered), stderr='')), \
            patch.object(ptf_runner, '_copy_container_file') as copy:
        with pytest.raises(ValueError, match='identity differs from host outcome'):
            ptf_runner.recover_host_outcome(path)
    copy.assert_not_called()
    assert ptf_runner.load_outcome(path) == original
