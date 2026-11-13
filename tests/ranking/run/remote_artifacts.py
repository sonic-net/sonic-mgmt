"""One-shot remote file operations for a single UUID case run."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

if __name__ != '__main__':
    from tests.ranking.common.artifact_contract import OUTCOME_FILE, RUN_LOG_FILE


MAX_POLL_BYTES = 64 * 1024
RUN_ID = re.compile(r'[0-9a-f]{32}\Z')
FILE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*\Z')


def _strict_json(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(descriptor, 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError('unsafe outcome file')
        payload = source.read(MAX_POLL_BYTES + 1)
    if len(payload) > MAX_POLL_BYTES:
        raise ValueError('outcome is too large')
    return json.loads(payload.decode('utf-8'))


def _root(root, create=False):
    root = Path(root)
    if not root.is_absolute() or '..' in root.parts or root == Path('/'):
        raise ValueError('invalid artifact root')
    if create:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('unsafe artifact root')
    runs = root / 'runs'
    if create:
        runs.mkdir(mode=0o700, exist_ok=True)
    if runs.is_symlink() or not runs.is_dir():
        raise ValueError('unsafe runs directory')
    return runs


def _run(root, run_id, create=False):
    if not isinstance(run_id, str) or RUN_ID.fullmatch(run_id) is None:
        raise ValueError('invalid run id')
    runs = _root(root, create=create)
    path = runs / run_id
    if create:
        path.mkdir(mode=0o700, exist_ok=False)
    if path.is_symlink() or not path.is_dir():
        raise ValueError('unsafe run directory')
    return path


def _manifest(path):
    result = {}
    for entry in sorted(path.iterdir()):
        if entry.is_symlink() or not entry.is_file() or FILE_NAME.fullmatch(entry.name) is None:
            raise ValueError('unsafe artifact: ' + entry.name)
        digest = hashlib.sha256()
        with entry.open('rb') as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(chunk)
        result[entry.name] = digest.hexdigest()
    return result


def _file_request(value):
    if (not isinstance(value, dict) or set(value) != {'name', 'sha256'} or
            not isinstance(value['name'], str) or
            FILE_NAME.fullmatch(value['name']) is None or
            not isinstance(value['sha256'], str) or
            re.fullmatch(r'[0-9a-f]{64}', value['sha256']) is None):
        raise ValueError('invalid artifact file request')
    return value['name'], value['sha256']


def operate(action, root, run_id, value=None):
    """Execute one bounded operation; no background process is installed."""
    if action == 'create':
        _run(root, run_id, create=True)
        return {'created': True}
    path = _run(root, run_id)
    if action == 'poll':
        if (not isinstance(value, dict) or set(value) != {'offset', 'limit'} or
                type(value['offset']) is not int or value['offset'] < 0 or
                type(value['limit']) is not int or
                not 0 < value['limit'] <= MAX_POLL_BYTES):
            raise ValueError('invalid poll range')
        log = path / RUN_LOG_FILE
        if log.exists():
            if log.is_symlink() or not log.is_file():
                raise ValueError('unsafe run log')
            with log.open('rb') as source:
                source.seek(value['offset'])
                payload = source.read(value['limit'])
        else:
            payload = b''
        return {
            'data': base64.b64encode(payload).decode('ascii'),
            'offset': value['offset'] + len(payload),
            'outcome': _strict_json(path / OUTCOME_FILE),
        }
    if action == 'inspect':
        return _manifest(path)
    if action == 'export':
        name, expected = _file_request(value)
        if _manifest(path).get(name) != expected:
            raise ValueError('source artifact hash changed')
        with (path / name).open('rb') as source:
            shutil.copyfileobj(source, sys.stdout.buffer)
        return None
    if action == 'import':
        name, expected = _file_request(value)
        target = path / name
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600)
        digest = hashlib.sha256()
        try:
            with os.fdopen(descriptor, 'wb') as destination:
                for chunk in iter(lambda: sys.stdin.buffer.read(1024 * 1024), b''):
                    digest.update(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            if digest.hexdigest() != expected:
                raise ValueError('imported artifact hash differs')
        except Exception:
            try:
                target.unlink()
            except FileNotFoundError:
                pass
            raise
        return None
    if action == 'delete':
        for entry in path.iterdir():
            if entry.is_symlink() or not entry.is_file():
                raise ValueError('unsafe artifact during delete')
            entry.unlink()
        path.rmdir()
        return {'deleted': True}
    raise ValueError('unknown artifact operation')


if __name__ == '__main__':
    result = operate(sys.argv[1], sys.argv[2], sys.argv[3], json.loads(sys.argv[4]))
    if sys.argv[1] != 'export':
        print(json.dumps(result, sort_keys=True))
