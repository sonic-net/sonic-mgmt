"""Attach to, validate and execute inside one existing PTF container."""

import base64
from collections.abc import Mapping
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import time
import uuid

from tests.ranking.common.artifact_contract import (
    CONSOLE_HEADER, INTERNAL_HEADER, OUTCOME_FILE, RUN_LOG_FILE,
)
from tests.ranking.run.ptf_runner import GRACE_SECONDS
from tests.ranking.run.live_console import LiveConsole


CONTAINER_ID = re.compile(r'[0-9a-f]{64}\Z')
CONTAINER_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*\Z')
POLL_BYTES = 64 * 1024
POLL_SECONDS = 1.0
DISPATCH_GRACE_SECONDS = 4 * GRACE_SECONDS
STAGING_ROOT = '/tmp/ranking'


CREATE_ROOT = r'''# RANKING_SESSION_CREATE
import os, pathlib, re, sys
root, session = pathlib.Path(sys.argv[1]), sys.argv[2]
if not root.is_absolute() or root == pathlib.Path('/') or '..' in root.parts:
    raise ValueError('invalid staging root')
if re.fullmatch(r'[0-9a-f]{32}', session) is None:
    raise ValueError('invalid session id')
root.mkdir(mode=0o700, parents=True, exist_ok=True)
(root / session).mkdir(mode=0o700, exist_ok=False)
'''

CREATE_COLLECTOR = r'''# RANKING_COLLECTOR_CREATE
import pathlib, sys
path = pathlib.Path(sys.argv[1])
if not path.is_absolute() or path == pathlib.Path('/') or '..' in path.parts:
    raise ValueError('invalid collector directory')
path.mkdir(mode=0o700, parents=True, exist_ok=True)
if path.is_symlink() or not path.is_dir() or path.resolve() != path:
    raise ValueError('unsafe collector directory')
'''

WRITE_RUNNER = r'''# RANKING_RUNNER_WRITE
import base64, hashlib, os, pathlib, re, sys
root, session, expected, payload = (
    pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4])
if re.fullmatch(r'[0-9a-f]{32}', session) is None:
    raise ValueError('invalid session id')
directory = root / session
if directory.is_symlink() or not directory.is_dir():
    raise ValueError('session root is missing')
content = base64.b64decode(payload.encode('ascii'), validate=True)
if hashlib.sha256(content).hexdigest() != expected:
    raise ValueError('runner digest differs')
target = directory / 'ptf_runner.py'
fd = os.open(
    target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o500)
with os.fdopen(fd, 'wb') as output:
    output.write(content)
    output.flush()
    os.fsync(output.fileno())
'''

REMOVE_ROOT = r'''# RANKING_SESSION_REMOVE
import pathlib, re, shutil, sys
root, session = pathlib.Path(sys.argv[1]), sys.argv[2]
if not root.is_absolute() or root == pathlib.Path('/') or '..' in root.parts:
    raise ValueError('invalid staging root')
if re.fullmatch(r'[0-9a-f]{32}', session) is None:
    raise ValueError('invalid session id')
target = root / session
if target.is_symlink():
    raise ValueError('unsafe session root')
if target.exists():
    shutil.rmtree(target)
'''


def command(host, argv, operation=None):
    result = host.command(
        argv=argv, module_ignore_errors=True, verbose=False)
    if (not isinstance(result, Mapping) or type(result.get('rc')) is not int or
            result['rc'] != 0 or any(result.get(flag) for flag in (
                'failed', 'unreachable', 'skipped'))):
        detail = result.get('stderr') or result.get('msg') \
            if isinstance(result, Mapping) else result
        raise RuntimeError('{} failed: {}'.format(
            operation or ' '.join(argv[:2]), detail))
    return result


def inspect_container(host, name):
    if not isinstance(name, str) or CONTAINER_NAME.fullmatch(name) is None:
        raise ValueError('invalid PTF container name')
    result = command(
        host, ['docker', 'container', 'inspect', name], 'container inspection')
    try:
        value = json.loads(result.get('stdout', ''))
    except (TypeError, ValueError) as error:
        raise RuntimeError('PTF container inspection is invalid') from error
    if (not isinstance(value, list) or len(value) != 1 or
            not isinstance(value[0], dict)):
        raise RuntimeError('PTF container inspection is invalid')
    inspected = value[0]
    state = inspected.get('State')
    identity = inspected.get('Id')
    if (inspected.get('Name') != '/' + name or
            not isinstance(identity, str) or
            CONTAINER_ID.fullmatch(identity) is None or
            not isinstance(state, dict) or state.get('Running') is not True):
        raise RuntimeError(
            'PTF container is not running with a stable identity')
    return identity


def dispatch(host, session, request):
    """Start the runner detached; polling supplies user-visible output."""
    payload = base64.b64encode(
        json.dumps(request, sort_keys=True, allow_nan=False).encode('utf-8')
    ).decode('ascii')
    command(host, [
        'docker', 'exec', '-d', session['container_id'], 'python3',
        session['runner_path'], '--request-base64', payload,
    ], 'PTF dispatch')


def _runner_source(path):
    prefix = (
        'CONSOLE_HEADER = {!r}\n'
        'INTERNAL_HEADER = {!r}\n'
        'OUTCOME_FILE = {!r}\n'
        'RUN_LOG_FILE = {!r}\n'
    ).format(CONSOLE_HEADER, INTERNAL_HEADER, OUTCOME_FILE, RUN_LOG_FILE)
    return prefix.encode('utf-8') + Path(path).read_bytes()


def wait(host, session, run_id, request, case, mode='compact', sink=None,
         clock=None, sleeper=None, console=None):
    """Poll the one-shot artifact helper until the current runner exits."""
    from tests.ranking.run import artifact_collection

    now = time.monotonic if clock is None else clock
    pause = time.sleep if sleeper is None else sleeper
    started_at = now()
    start_deadline = started_at + DISPATCH_GRACE_SECONDS
    deadline = (started_at + request['timeout_s'] + DISPATCH_GRACE_SECONDS +
                GRACE_SECONDS)
    offset = len(CONSOLE_HEADER.encode())
    console = LiveConsole(mode, case, sink) if console is None else console
    console.start()
    while True:
        if now() >= deadline:
            raise RuntimeError('PTF runner exit was not confirmed')
        value = artifact_collection.remote_operation(
            host, session, run_id, 'poll',
            {'offset': offset, 'limit': POLL_BYTES}, ptf_container=True)
        previous = offset
        payload = base64.b64decode(
            value['data'].encode('ascii'), validate=True)
        terminal = value.get('outcome')
        boundary = terminal.get('console_log_bytes') \
            if isinstance(terminal, dict) else None
        if type(boundary) is int:
            payload = payload[:max(0, boundary - previous)]
        if payload:
            console.feed(payload)
        offset = min(value['offset'], boundary) \
            if type(boundary) is int else value['offset']
        if terminal is not None:
            if (terminal.get('process_exited') is True and
                    type(terminal.get('console_log_bytes')) is int and
                    offset >= terminal['console_log_bytes']):
                return console, now() - started_at
        elif now() >= start_deadline:
            raise RuntimeError('PTF runner start was not confirmed')
        pause(POLL_SECONDS)


def _path(value, field):
    if (not isinstance(value, str) or not value.startswith('/') or
            str(PurePosixPath(value)) != value or value == '/'):
        raise ValueError('{} must be an absolute canonical path'.format(field))
    return value


def _validate_paths(host, container_id, config):
    checks = (
        ('-x', config['ptf_executable']),
        ('-d', config['ptf_workdir']),
        ('-d', config['ptf_case_dir']),
        ('-d', config['collector_dir']),
    )
    for mode, path in checks:
        _path(path, 'PTF runtime path')
        command(
            host, ['docker', 'exec', container_id, 'test', mode, path],
            'PTF runtime path validation')


def open_session(host, config):
    """Validate Ready inputs and inject only the current runner file."""
    container_name = config['ptf_container']
    container_id = inspect_container(host, container_name)
    collector = _path(config['collector_dir'], 'collector_dir')
    command(
        host, ['docker', 'exec', container_id, 'python3', '-c',
               CREATE_COLLECTOR, collector],
        'PTF collector directory creation')
    _validate_paths(host, container_id, config)
    session_id = uuid.uuid4().hex
    base = STAGING_ROOT
    root = str(PurePosixPath(base) / session_id)
    runner = Path(config['runner_path']).resolve()
    content = _runner_source(runner)
    try:
        command(
            host, ['python3', '-c', CREATE_ROOT, base, session_id],
            'host session creation')
        command(
            host, ['docker', 'exec', container_id, 'python3', '-c',
                   CREATE_ROOT, base, session_id],
            'container session creation')
        command(
            host, ['docker', 'exec', container_id, 'python3', '-c',
                   WRITE_RUNNER,
                   base, session_id, hashlib.sha256(content).hexdigest(),
                   base64.b64encode(content).decode('ascii')],
            'container runner injection')
    except Exception:
        temporary = {
            'session_id': session_id, 'container_id': container_id,
            'root': root, 'staging_base': base,
        }
        close_session(host, temporary, ignore_errors=True)
        raise
    return {
        'session_id': session_id,
        'container_id': container_id,
        'root': root,
        'staging_base': base,
        'runner_path': root + '/ptf_runner.py',
    }


def close_session(host, value, ignore_errors=False):
    """Remove this process's UUID roots."""
    errors = []
    try:
        command(
            host, ['docker', 'exec', value['container_id'], 'python3', '-c',
                   REMOVE_ROOT, value['staging_base'], value['session_id']],
            'container session cleanup')
    except Exception as error:
        errors.append(str(error))
    try:
        command(
            host, ['python3', '-c', REMOVE_ROOT, value['staging_base'],
                   value['session_id']], 'host session cleanup')
    except Exception as error:
        errors.append(str(error))
    if errors and not ignore_errors:
        raise RuntimeError('session cleanup failed: ' + '; '.join(errors))
    return not errors
