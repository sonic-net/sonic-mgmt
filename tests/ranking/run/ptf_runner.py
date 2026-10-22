"""Run one PTF process inside the existing test ptf_container."""

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import uuid

if __name__ != '__main__':
    from tests.ranking.common.artifact_contract import (
        CONSOLE_HEADER, INTERNAL_HEADER, OUTCOME_FILE, RUN_LOG_FILE,
    )


PHASE = 'ptf'
RUN_LOG = RUN_LOG_FILE
GRACE_SECONDS = 5
TIMEOUT_RC = 124
SPAWN_ERROR_RC = 127
ERROR_RC = 1
MAX_REQUEST_BYTES = 1024 * 1024
ENV_PATTERN = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')
CONTAINER_ID_PATTERN = re.compile(r'[0-9a-f]{64}\Z')
COLLECTOR_NAME = re.compile(r'[A-Za-z_]\w*_[A-Za-z_]\w*\.json\Z')
REQUEST_FIELDS = frozenset((
    'argv', 'env', 'cwd', 'run_dir', 'timeout_s', 'container_id',
    'collector_source',
))


def _atomic_json(directory, value):
    target = directory / OUTCOME_FILE
    temporary = directory / ('.{}-{}'.format(OUTCOME_FILE, uuid.uuid4().hex))
    text = json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n'
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _append_internal_log(run_dir, outcome):
    internal = run_dir / 'ptf.log'
    with (run_dir / RUN_LOG).open('ab') as output:
        outcome['console_log_bytes'] = output.tell()
        output.write(INTERNAL_HEADER.encode())
        if internal.is_file() and not internal.is_symlink():
            payload = internal.read_bytes()
            output.write(payload)
            outcome['internal_log_sha256'] = hashlib.sha256(payload).hexdigest()
            internal.unlink()
        output.flush()
        os.fsync(output.fileno())


def _terminate(process):
    """Terminate only the process group created by this runner invocation."""
    for action in (signal.SIGTERM, signal.SIGKILL):
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, action)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=GRACE_SECONDS)
            return
        except subprocess.TimeoutExpired:
            continue
    if process.poll() is None:
        raise RuntimeError('PTF process group survived TERM and KILL')


def run_ptf(argv, *, env, cwd, run_dir, timeout_s, container_id=None):
    run_path = Path(run_dir)
    if run_path.is_symlink() or not run_path.is_dir():
        raise ValueError('run directory must already exist')
    outcome = {
        'phase': PHASE,
        'argv': list(argv),
        'timeout_s': timeout_s,
        'rc': ERROR_RC,
        'timed_out': False,
        'process_exited': False,
    }
    if container_id is not None:
        outcome['container_id'] = container_id
    process = None
    try:
        with (run_path / RUN_LOG).open('xb') as output:
            output.write(CONSOLE_HEADER.encode())
            output.flush()
            process = subprocess.Popen(
                list(argv), shell=False, start_new_session=True, cwd=cwd, env=env,
                stdout=output, stderr=subprocess.STDOUT)
            _atomic_json(run_path, outcome)
            try:
                outcome['rc'] = process.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                outcome.update(rc=TIMEOUT_RC, timed_out=True)
            finally:
                _terminate(process)
                process.wait(timeout=GRACE_SECONDS)
                outcome['process_exited'] = True
    except OSError as error:
        outcome.update(rc=SPAWN_ERROR_RC, process_exited=True, error=str(error))
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        outcome['error'] = str(error)
    try:
        if (run_path / RUN_LOG).is_file():
            _append_internal_log(run_path, outcome)
    except OSError as error:
        outcome['log_error'] = str(error)
    _atomic_json(run_path, outcome)
    return outcome


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate request key: ' + key)
        value[key] = item
    return value


def _constant(value):
    raise ValueError('invalid JSON constant: ' + value)


def _canonical_path(value, field):
    if (not isinstance(value, str) or not os.path.isabs(value) or
            os.path.normpath(value) != value or '\x00' in value):
        raise ValueError('{} must be an absolute canonical path'.format(field))
    return value


def _load_request(arguments):
    if len(arguments) != 2 or arguments[0] != '--request-base64':
        raise ValueError('usage: ptf_runner --request-base64 <base64>')
    try:
        payload = base64.b64decode(arguments[1].encode('ascii'), validate=True)
        if len(payload) > MAX_REQUEST_BYTES:
            raise ValueError('request is too large')
        value = json.loads(payload.decode('utf-8'), object_pairs_hook=_unique,
                           parse_constant=_constant)
    except (UnicodeError, binascii.Error, ValueError) as error:
        raise ValueError('request is not valid strict base64 JSON') from error
    if not isinstance(value, dict) or set(value) != REQUEST_FIELDS:
        raise ValueError('request fields are invalid')
    if (not isinstance(value['argv'], list) or not value['argv'] or
            any(not isinstance(item, str) or '\x00' in item for item in value['argv'])):
        raise ValueError('request argv is invalid')
    if (not isinstance(value['env'], dict) or any(
            not isinstance(key, str) or ENV_PATTERN.fullmatch(key) is None or
            not isinstance(item, str) or '\x00' in item
            for key, item in value['env'].items())):
        raise ValueError('request env is invalid')
    _canonical_path(value['cwd'], 'cwd')
    _canonical_path(value['run_dir'], 'run_dir')
    collector = _canonical_path(value['collector_source'], 'collector_source')
    if COLLECTOR_NAME.fullmatch(Path(collector).name) is None:
        raise ValueError('collector_source is invalid')
    if type(value['timeout_s']) is not int or value['timeout_s'] <= 0:
        raise ValueError('timeout_s must be positive')
    if (not isinstance(value['container_id'], str) or
            CONTAINER_ID_PATTERN.fullmatch(value['container_id']) is None):
        raise ValueError('container_id is invalid')
    return value


def _move_collector(source, run_dir):
    source = Path(source)
    if not source.exists():
        return
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as opened:
        if not stat.S_ISREG(os.fstat(opened.fileno()).st_mode):
            raise ValueError('collector is not a regular file')
    destination = run_dir / source.name
    if destination.exists() or destination.is_symlink():
        raise ValueError('collector destination already exists')
    os.replace(source, destination)


def main(argv=None):
    try:
        request = _load_request(list(sys.argv[1:] if argv is None else argv))
        collector = Path(request['collector_source'])
        if collector.exists():
            if collector.is_symlink() or not collector.is_file():
                raise ValueError('collector source is unsafe')
            collector.unlink()
        environment = dict(os.environ)
        environment.update(request['env'])
        outcome = run_ptf(
            request['argv'], env=environment, cwd=request['cwd'],
            run_dir=request['run_dir'], timeout_s=request['timeout_s'],
            container_id=request['container_id'])
        if outcome['process_exited']:
            try:
                _move_collector(collector, Path(request['run_dir']))
            except (OSError, ValueError) as error:
                outcome['error'] = 'collector archive failed: {}'.format(error)
            _atomic_json(Path(request['run_dir']), outcome)
        code = outcome['rc']
        if not outcome['process_exited'] or outcome.get('error') or outcome.get('log_error'):
            code = code or ERROR_RC
        return code
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print('ptf_runner: {}'.format(error), file=sys.stderr)
        return ERROR_RC


if __name__ == '__main__':
    sys.exit(main())
