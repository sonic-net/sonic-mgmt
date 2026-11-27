import json
import os
import signal
import subprocess
import sys
from unittest.mock import Mock, patch

import pytest

from tests.ranking import ptf_runner


def test_timeout_terminates_only_owned_group(tmp_path):
    process = Mock(pid=4321, returncode=-signal.SIGTERM)
    process.wait.side_effect = [subprocess.TimeoutExpired(['ptf'], 1),
                                -signal.SIGTERM]
    process.poll.side_effect = [None, -signal.SIGTERM]
    with patch.object(ptf_runner.subprocess, 'Popen', return_value=process) as launch, \
         patch.object(ptf_runner, 'process_birth', return_value='birth-a'), \
         patch.object(ptf_runner.os, 'killpg') as kill:
        result = ptf_runner.run_ptf(['ptf', 'sairoute.RouteA'], env={},
                                   cwd=str(tmp_path),
                                   run_dir=str(tmp_path / 'run'), timeout_s=1)
    assert launch.call_args.kwargs['start_new_session'] is True
    assert launch.call_args.kwargs['shell'] is False
    kill.assert_called_once_with(4321, signal.SIGTERM)
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
    process = Mock(pid=5150, returncode=-signal.SIGKILL)
    process.wait.side_effect = [subprocess.TimeoutExpired(['ptf'], 1),
                                subprocess.TimeoutExpired(['ptf'], 5),
                                -signal.SIGKILL]
    process.poll.side_effect = [None, None, -signal.SIGKILL]
    with patch.object(ptf_runner.subprocess, 'Popen', return_value=process), \
         patch.object(ptf_runner, 'process_birth', return_value='birth-b'), \
         patch.object(ptf_runner.os, 'killpg') as kill:
        result = ptf_runner.run_ptf(['ptf'], env={}, cwd=str(tmp_path),
                                   run_dir=str(tmp_path / 'run'), timeout_s=1)
    assert [call.args for call in kill.call_args_list] == [
        (5150, signal.SIGTERM), (5150, signal.SIGKILL)]
    assert result['rc'] == 124 and result['timed_out'] is True
    assert result['process_exited'] is True


def test_recycled_pid_birth_change_never_signaled(tmp_path):
    process = Mock(pid=6161, returncode=0)
    process.wait.side_effect = [subprocess.TimeoutExpired(['ptf'], 1), 0]
    process.poll.side_effect = [None, 0]
    with patch.object(ptf_runner.subprocess, 'Popen', return_value=process), \
         patch.object(ptf_runner, 'process_birth',
                      side_effect=['birth-a', 'birth-z']) as birth, \
         patch.object(ptf_runner.os, 'killpg') as kill:
        result = ptf_runner.run_ptf(['ptf'], env={}, cwd=str(tmp_path),
                                   run_dir=str(tmp_path / 'run'), timeout_s=1)
    kill.assert_not_called()
    assert birth.call_count == 2
    assert result['rc'] == 124 and result['timed_out'] is True
    assert result['process_exited'] is True


def test_unproven_exit_records_process_not_exited(tmp_path):
    process = Mock(pid=7171, returncode=None)
    process.wait.side_effect = subprocess.TimeoutExpired(['ptf'], 1)
    process.poll.return_value = None
    with patch.object(ptf_runner.subprocess, 'Popen', return_value=process), \
         patch.object(ptf_runner, 'process_birth', return_value='birth-c'), \
         patch.object(ptf_runner.os, 'killpg'):
        result = ptf_runner.run_ptf(['ptf'], env={}, cwd=str(tmp_path),
                                   run_dir=str(tmp_path / 'run'), timeout_s=1)
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


def _mac_stat_reader(pid):
    try:
        pgid = os.getpgid(pid)
    except OSError:
        return None
    tail = ['S', '1', str(pgid), str(pgid), '0', '-1', '0'] + ['0'] * 12 + ['4242']
    return '{0} (python3) {1}'.format(pid, ' '.join(tail))


def test_real_child_timeout_terminates_owned_group(tmp_path):
    cwd = tmp_path / 'cwd'
    cwd.mkdir()
    real_killpg = os.killpg
    with patch.object(ptf_runner.os, 'killpg', side_effect=real_killpg) as kill:
        result = ptf_runner.run_ptf(
            [sys.executable, '-c', 'import time; time.sleep(60)'],
            env=dict(os.environ), cwd=str(cwd), run_dir=str(tmp_path / 'run'),
            timeout_s=1, birth_reader=_mac_stat_reader)
    assert result['timed_out'] is True
    assert result['rc'] == 124
    assert result['process_exited'] is True
    assert result['birth'] == '4242'
    assert kill.call_args.args == (result['pid'], signal.SIGTERM)
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


def test_main_runs_request_and_prints_outcome(tmp_path, capsys):
    code = ptf_runner.main(['--request', str(_request(tmp_path))])
    outcome = json.loads(capsys.readouterr().out)
    assert code == 0
    assert outcome['rc'] == 0 and outcome['process_exited'] is True
    assert json.loads(
        (tmp_path / 'runs' / 'run-a' / 'outcome.json').read_text()) == outcome
    assert (tmp_path / 'runs' / 'run-a' / 'stdout.log').read_text().strip() == \
        'main-done'


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
