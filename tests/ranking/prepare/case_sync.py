"""Publish one complete PTF case tree without retaining deployment state."""

from collections.abc import Mapping
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import stat
import tarfile
import tempfile
import uuid
import warnings

import pytest


IGNORED_PARTS = frozenset(('.git', '__pycache__', '.pytest_cache', '.DS_Store'))

TARGET_PROBE = r'''# TARGET_PROBE
import os
import sys

target = sys.argv[1]
if not os.path.lexists(target):
    raise SystemExit(3)
if os.path.islink(target) or not os.path.isdir(target):
    raise SystemExit(4)
'''

PUBLISH_CASES = r'''# PUBLISH_CASES
import errno
import json
import os
from pathlib import PurePosixPath
import shutil
import sys
import tarfile

archive, target, token, force_text = sys.argv[1:]
force = force_text == '1'
temporary = target + '.prepare-' + token
backup = target + '.backup-' + token

def remove_owned(path):
    if os.path.islink(path) or os.path.isfile(path):
        os.unlink(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)

for owned in (temporary, backup):
    if os.path.lexists(owned):
        remove_owned(owned)

parent = os.path.dirname(target)
os.makedirs(parent, exist_ok=True)
os.mkdir(temporary, 0o700)
moved_old = False
try:
    with tarfile.open(archive, 'r') as bundle:
        for member in bundle.getmembers():
            path = PurePosixPath(member.name)
            if (not path.parts or path.is_absolute() or '..' in path.parts
                    or str(path) != member.name or member.issym() or member.islnk()
                    or not (member.isdir() or member.isfile())):
                raise ValueError('unsafe archive member: {!r}'.format(member.name))
        bundle.extractall(temporary)
    if os.path.lexists(target):
        if os.path.islink(target) or not os.path.isdir(target):
            raise ValueError('target exists but is not a directory')
        if not force:
            raise ValueError('target unexpectedly exists without force')
        try:
            os.rename(target, backup)
            moved_old = True
        except OSError as error:
            if error.errno != errno.EXDEV:
                raise
            shutil.copytree(target, backup, symlinks=True)
            moved_old = True
            remove_owned(target)
    os.rename(temporary, target)
    if moved_old:
        shutil.rmtree(backup)
    print(json.dumps({'status': 'replaced' if moved_old else 'synchronized'}))
except BaseException:
    if moved_old and os.path.isdir(backup):
        if os.path.lexists(target):
            remove_owned(target)
        if not os.path.lexists(target):
            os.rename(backup, target)
    elif os.path.lexists(backup):
        remove_owned(backup)
    if os.path.lexists(temporary):
        remove_owned(temporary)
    raise
'''


def _safe_relative(value):
    if not isinstance(value, str):
        raise ValueError('unsafe archive target: {!r}'.format(value))
    path = PurePosixPath(value)
    if (not path.parts or path.is_absolute() or '..' in path.parts
            or str(path) != value or '\\' in value
            or any(ord(character) < 32 or ord(character) == 127
                   for character in value)):
        raise ValueError('unsafe archive target: {!r}'.format(value))
    return value


def _source_type(path):
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        raise ValueError('case source is a symlink: {}'.format(path))
    if stat.S_ISDIR(mode):
        return True
    if stat.S_ISREG(mode):
        return False
    raise ValueError('case source is not a regular file or directory: {}'.format(path))


def _archive_inputs(source, overlays):
    source = Path(source)
    if not source.is_dir() or source.is_symlink():
        raise ValueError('PTF case source must be a real directory: {}'.format(source))
    members = {}

    def add(path, name, directory):
        _safe_relative(name)
        members[name] = (path, directory)

    for item in sorted(source.rglob('*')):
        relative = item.relative_to(source)
        if (any(part in IGNORED_PARTS for part in relative.parts)
                or item.suffix in ('.pyc', '.pyo')):
            continue
        directory = _source_type(item)
        add(item, relative.as_posix(), directory)
    for overlay in overlays:
        if not isinstance(overlay, Mapping) or set(overlay) != {'source', 'target'}:
            raise ValueError('case overlay must contain source and target')
        path = Path(overlay['source'])
        if _source_type(path):
            raise ValueError('case overlay must be a regular file: {}'.format(path))
        add(path, _safe_relative(overlay['target']), False)
    return members


def _create_archive(source, overlays, destination):
    """Create one archive; later overlays replace same-named case members."""
    members = _archive_inputs(source, overlays)
    with tarfile.open(str(destination), 'w') as archive:
        for name in sorted(members, key=lambda value: (
                len(PurePosixPath(value).parts), value)):
            source_path, directory = members[name]
            info = tarfile.TarInfo(name)
            info.mode = stat.S_IMODE(source_path.lstat().st_mode)
            if directory:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
                continue
            descriptor = os.open(str(source_path), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, 'rb') as content:
                current = os.fstat(content.fileno())
                if not stat.S_ISREG(current.st_mode):
                    raise ValueError(
                        'case source is not a regular file: {}'.format(source_path))
                info.size = current.st_size
                archive.addfile(info, content)


def _result(host, result, operation, accepted=(0,)):
    if (not isinstance(result, Mapping) or result.get('unreachable')
            or result.get('skipped') or type(result.get('rc')) is not int
            or not isinstance(result.get('stdout', ''), str)
            or not isinstance(result.get('stderr', ''), str)
            or result['rc'] not in accepted):
        detail = ''
        if isinstance(result, Mapping):
            detail = result.get('stderr') or result.get('stdout') or result.get('msg') or ''
        raise RuntimeError('{} failed on {}{}'.format(
            operation, getattr(host, 'hostname', 'PTF'),
            ': ' + str(detail).strip().split('\n')[-1][-300:] if detail else ''))
    return result


def _command(host, argv, operation, accepted=(0,)):
    try:
        value = host.command(argv=list(argv), module_ignore_errors=True)
    except Exception as error:
        raise RuntimeError('{} could not complete'.format(operation)) from error
    return _result(host, value, operation, accepted)


def _shell(host, command, operation):
    try:
        value = host.shell(
            cmd='set -o pipefail; ' + command,
            executable='/bin/bash', module_ignore_errors=True)
    except Exception as error:
        raise RuntimeError('{} could not complete'.format(operation)) from error
    return _result(host, value, operation)


def _copy(host, source, destination):
    try:
        value = host.copy(src=str(source), dest=destination, mode='0600')
    except Exception as error:
        raise RuntimeError('case bundle upload could not complete') from error
    if (not isinstance(value, Mapping) or not value or value.get('failed')
            or value.get('unreachable') or value.get('skipped')
            or value.get('dest') != destination):
        raise RuntimeError('case bundle upload failed without destination evidence')


def _sync_description(description):
    if not isinstance(description, Mapping):
        raise ValueError('environment description must be an object')
    value = description.get('case_sync')
    if not isinstance(value, Mapping):
        raise ValueError('environment description requires case_sync')
    if set(value) != {'container', 'target', 'overlays'}:
        raise ValueError('case_sync must contain container, target and overlays')
    container = value['container']
    if (not isinstance(container, str) or not container
            or any(character not in
                   'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-'
                   for character in container)):
        raise ValueError('case_sync container is invalid')
    target = value['target']
    target_path = PurePosixPath(target) if isinstance(target, str) else PurePosixPath('.')
    if (not isinstance(target, str) or not target_path.is_absolute()
            or str(target_path) != target or '..' in target_path.parts
            or len(target_path.parts) < 3):
        raise ValueError('case_sync target must be a specific canonical absolute path')
    overlays = value['overlays']
    if not isinstance(overlays, (tuple, list)):
        raise ValueError('case_sync overlays must be a list')
    return container, target, overlays


def sync_cases(context, description):
    """Skip an existing target, or atomically publish one complete replacement."""
    container, target, overlays = _sync_description(description)
    probe = _command(
        context.ptfhost,
        ['docker', 'exec', container, 'python3', '-c', TARGET_PROBE, target],
        'case target inspection', accepted=(0, 3, 4))
    if probe['rc'] == 4:
        raise ValueError('PTF case target exists but is not a directory: {}'.format(target))
    if probe['rc'] == 0 and not context.force_sync:
        warnings.warn(pytest.PytestWarning(
            'PTF case target already exists; existing content was not compared '
            'with the source and synchronization was skipped. Use '
            '--ranking-force-sync to replace it.'))
        return {'status': 'skipped', 'container': container, 'target': target}

    token = uuid.uuid4().hex
    host_archive = '/tmp/.ranking-cases-{}.tar'.format(token)
    container_archive = '/tmp/.ranking-cases-{}.tar'.format(token)
    descriptor, local_name = tempfile.mkstemp(
        prefix='.ranking-cases-', suffix='.tar')
    os.close(descriptor)
    local_archive = Path(local_name)
    primary_error = None
    try:
        _create_archive(context.case_root / 'ptf', overlays, local_archive)
        _copy(context.ptfhost, local_archive, host_archive)
        stream = 'docker exec -i {} dd of={} status=none < {}'.format(
            shlex.quote(container), shlex.quote(container_archive),
            shlex.quote(host_archive))
        _shell(context.ptfhost, stream, 'case bundle stream')
        published = _command(
            context.ptfhost,
            ['docker', 'exec', container, 'python3', '-c', PUBLISH_CASES,
             container_archive, target, token, '1' if context.force_sync else '0'],
            'case bundle publication')
        try:
            result = json.loads(published['stdout'])
        except (TypeError, ValueError) as error:
            raise RuntimeError('case bundle publication returned invalid JSON') from error
        expected = 'replaced' if probe['rc'] == 0 else 'synchronized'
        if not isinstance(result, dict) or result.get('status') != expected:
            raise RuntimeError('case bundle publication returned unexpected status')
        return {'status': expected, 'container': container, 'target': target}
    except Exception as error:
        primary_error = error
        raise
    finally:
        cleanup_errors = []
        try:
            local_archive.unlink()
        except FileNotFoundError:
            pass
        for argv, operation in (
                (['docker', 'exec', container, 'rm', '-f', '--', container_archive],
                 'container bundle cleanup'),
                (['rm', '-f', '--', host_archive], 'host bundle cleanup')):
            try:
                _command(context.ptfhost, argv, operation)
            except RuntimeError as error:
                cleanup_errors.append(str(error))
        if cleanup_errors and primary_error is None:
            raise RuntimeError('; '.join(cleanup_errors))
