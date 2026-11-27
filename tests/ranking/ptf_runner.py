import json
import os
import signal
import subprocess
import sys
from pathlib import Path


PHASE = 'ptf'
OUTCOME_FILE = 'outcome.json'
STDOUT_LOG = 'stdout.log'
STDERR_LOG = 'stderr.log'
GRACE_SECONDS = 5
TIMEOUT_RC = 124
SPAWN_ERROR_RC = 127
REQUEST_FIELDS = ('argv', 'env', 'cwd', 'run_dir', 'timeout_s')


def _proc_stat(pid):
    with open('/proc/{0}/stat'.format(pid), 'r', encoding='utf-8') as handle:
        return handle.read()


def _parse_stat(text):
    if not isinstance(text, str):
        return None
    close = text.rfind(')')
    if close < 0:
        return None
    fields = text[close + 1:].split()
    if len(fields) < 20:
        return None
    return fields


def process_birth(pid, reader=None):
    if type(pid) is not int or pid <= 0:
        return None
    read = _proc_stat if reader is None else reader
    try:
        text = read(pid)
    except OSError:
        return None
    fields = _parse_stat(text)
    if fields is None:
        return None
    if fields[2] != str(pid):
        return None
    return fields[19]


def _write_outcome(run_path, outcome):
    (run_path / OUTCOME_FILE).write_text(
        json.dumps(outcome, sort_keys=True, indent=2, ensure_ascii=True,
                   allow_nan=False) + '\n', encoding='utf-8')


def _still_ours(process, birth, birth_reader):
    if process.poll() is not None:
        return False
    return process_birth(process.pid, reader=birth_reader) == birth


def _terminate(process, birth, birth_reader):
    if _still_ours(process, birth, birth_reader):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        return process.wait(timeout=GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    if _still_ours(process, birth, birth_reader):
        os.killpg(process.pid, signal.SIGKILL)
    try:
        return process.wait(timeout=GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        return None


def run_ptf(argv, *, env, cwd, run_dir, timeout_s, birth_reader=None) -> dict:
    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=False)
    arguments = list(argv)
    try:
        with open(run_path / STDOUT_LOG, 'wb') as stdout_log, \
                open(run_path / STDERR_LOG, 'wb') as stderr_log:
            process = subprocess.Popen(
                arguments, shell=False, start_new_session=True, cwd=cwd, env=env,
                stdout=stdout_log, stderr=stderr_log)
    except OSError as error:
        outcome = {
            'phase': PHASE, 'pid': None, 'group': None, 'birth': None,
            'argv': arguments, 'timeout_s': timeout_s, 'rc': SPAWN_ERROR_RC,
            'timed_out': False, 'process_exited': True, 'error': str(error),
        }
        _write_outcome(run_path, outcome)
        return outcome
    pid = process.pid
    birth = process_birth(pid, reader=birth_reader)
    timed_out = False
    observed = None
    try:
        observed = process.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        observed = _terminate(process, birth, birth_reader)
    outcome = {
        'phase': PHASE, 'pid': pid, 'group': pid, 'birth': birth,
        'argv': arguments, 'timeout_s': timeout_s,
        'rc': TIMEOUT_RC if timed_out else observed,
        'timed_out': timed_out, 'process_exited': observed is not None,
    }
    _write_outcome(run_path, outcome)
    return outcome


def merge_outcome(primary, collection_errors) -> dict:
    if not isinstance(primary, dict):
        raise ValueError('primary outcome must be an object')
    if not isinstance(collection_errors, list):
        raise ValueError('collection errors must be a list')
    merged = dict(primary)
    merged['collection_errors'] = list(collection_errors)
    merged['collected'] = False
    return merged


def _no_duplicates(pairs):
    result = {}
    for key, item in pairs:
        if key in result:
            raise ValueError('duplicate request key: {}'.format(key))
        result[key] = item
    return result


def _load_request(arguments):
    if len(arguments) != 2 or arguments[0] != '--request':
        raise ValueError('usage: ptf_runner --request <request.json>')
    text = Path(arguments[1]).read_text(encoding='utf-8')
    try:
        request = json.loads(text, object_pairs_hook=_no_duplicates)
    except ValueError as error:
        raise ValueError('request is not valid JSON: {}'.format(error)) from error
    if not isinstance(request, dict):
        raise ValueError('request must be a JSON object')
    for field in REQUEST_FIELDS:
        if field not in request:
            raise ValueError('request is missing field: {}'.format(field))
    if (not isinstance(request['argv'], list) or not request['argv'] or
            any(not isinstance(argument, str) for argument in request['argv'])):
        raise ValueError('request argv must be a non-empty string array')
    if (not isinstance(request['env'], dict) or
            any(not isinstance(key, str) or not isinstance(value, str)
                for key, value in request['env'].items())):
        raise ValueError('request env must map names to strings')
    for field in ('cwd', 'run_dir'):
        if not isinstance(request[field], str) or not request[field].strip():
            raise ValueError('request {} must be a non-empty path'.format(field))
    if type(request['timeout_s']) is not int or request['timeout_s'] <= 0:
        raise ValueError('request timeout_s must be a positive integer')
    return request


def main(argv=None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        request = _load_request(arguments)
        outcome = run_ptf(
            request['argv'], env=request['env'], cwd=request['cwd'],
            run_dir=request['run_dir'], timeout_s=request['timeout_s'])
    except (OSError, ValueError) as error:
        print('ptf_runner: {}'.format(error), file=sys.stderr)
        return 1
    print(json.dumps(outcome, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return 0 if outcome['rc'] == 0 else outcome['rc']


if __name__ == '__main__':
    sys.exit(main())
