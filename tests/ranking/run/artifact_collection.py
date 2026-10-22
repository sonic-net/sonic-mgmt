"""Transfer, verify and atomically publish one case's artifacts."""

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import tempfile

from tests.ranking.common.artifact_contract import OUTCOME_FILE, RUN_LOG_FILE
from tests.ranking.common.case_selection import validate_case_name
from tests.ranking.run import ptf_container as container_runtime


SHA256 = re.compile(r'[0-9a-f]{64}\Z')
SCRIPT = (
    'OUTCOME_FILE = {!r}\nRUN_LOG_FILE = {!r}\n'.format(
        OUTCOME_FILE, RUN_LOG_FILE) +
    (Path(__file__).resolve().parent / 'remote_artifacts.py').read_text(
        encoding='utf-8'))


def create_staging(output_root, case, run_id):
    validate_case_name(case)
    if re.fullmatch(r'[0-9a-f]{32}', run_id) is None:
        raise ValueError('invalid run id')
    root = Path(output_root).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('artifact root is unsafe')
    cases = root / 'cases'
    cases.mkdir(mode=0o700, exist_ok=True)
    staging = cases / '.{}-{}'.format(case, run_id)
    staging.mkdir(mode=0o700)
    return staging


def verify(staging, manifest, case):
    """Verify required files and their container-recorded SHA256 values."""
    staging = Path(staging)
    collector = case.replace('.', '_') + '.json'
    allowed = {OUTCOME_FILE, RUN_LOG_FILE, 'ptf.pcap', collector}
    if (not isinstance(manifest, dict) or
            not {OUTCOME_FILE, RUN_LOG_FILE}.issubset(manifest) or
            set(manifest).difference(allowed) or any(
                not isinstance(value, str) or SHA256.fullmatch(value) is None
                for value in manifest.values())):
        raise ValueError('remote artifact manifest is incomplete or invalid')
    observed = {entry.name for entry in staging.iterdir()}
    if observed != set(manifest):
        raise ValueError(
            'controller staging files differ from remote manifest')
    for name, expected in manifest.items():
        path = staging / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('unsafe controller artifact: ' + name)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            raise ValueError('controller artifact hash differs: ' + name)
    return True


def _safe_remove(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('unsafe case archive directory')
    for entry in directory.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise ValueError('unsafe case archive content')
    shutil.rmtree(directory)


def _output_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise ValueError('unsafe case output directory: ' + str(path))


def _atomic_bytes(path, payload):
    descriptor, temporary = tempfile.mkstemp(
        prefix='.{}-'.format(path.name), dir=str(path.parent))
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _remove_regular_file(path):
    if not os.path.lexists(path):
        return
    if path.is_symlink() or not path.is_file():
        raise ValueError('unsafe case output file: ' + str(path))
    path.unlink()


def _snapshot_regular_file(path):
    if not os.path.lexists(path):
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError('unsafe case output file: ' + str(path))
    return path.read_bytes()


def _restore_file(path, payload):
    if payload is None:
        _remove_regular_file(path)
    else:
        _atomic_bytes(path, payload)


def publish(staging, case, result):
    """Publish one merged case result plus its log and optional capture."""
    validate_case_name(case)
    if not isinstance(result, dict) or result.get('case') != case:
        raise ValueError('case result identity differs from requested case')
    staging = Path(staging)
    module, cls = case.split('.')
    module_root = staging.parent / module
    results = module_root / 'results'
    logs = module_root / 'logs'
    pcaps = module_root / 'pcaps'
    for directory in (module_root, results, logs):
        _output_directory(directory)

    result_path = results / (cls + '.json')
    log_path = logs / (cls + '.log')
    pcap_path = pcaps / (cls + '.pcap')
    source_pcap = staging / 'ptf.pcap'
    payload = json.dumps(
        result, indent=2, sort_keys=True, ensure_ascii=True,
        allow_nan=False).encode('utf-8') + b'\n'
    new_log = (staging / RUN_LOG_FILE).read_bytes()
    new_pcap = source_pcap.read_bytes() if source_pcap.exists() else None
    previous = {
        log_path: _snapshot_regular_file(log_path),
        pcap_path: _snapshot_regular_file(pcap_path),
        result_path: _snapshot_regular_file(result_path),
    }
    changed = []
    try:
        _atomic_bytes(log_path, new_log)
        changed.append(log_path)
        if new_pcap is not None:
            _output_directory(pcaps)
            _atomic_bytes(pcap_path, new_pcap)
        else:
            _remove_regular_file(pcap_path)
        changed.append(pcap_path)
        _atomic_bytes(result_path, payload)
        changed.append(result_path)
    except Exception as error:
        try:
            for path in reversed(changed):
                _restore_file(path, previous[path])
        except Exception as rollback_error:
            raise RuntimeError(
                'case output publish and rollback both failed: {}'.format(
                    rollback_error)) from error
        raise

    published_pcap = pcap_path if new_pcap is not None else None
    _safe_remove(staging)
    return {'result': result_path, 'log': log_path, 'pcap': published_pcap}


def discard(staging):
    path = Path(staging)
    if path.exists() or path.is_symlink():
        _safe_remove(path)


def _argv(session, run_id, action, value, in_container):
    root = session['root']
    command = ['python3', '-c', SCRIPT, action, root, run_id,
               json.dumps(value, sort_keys=True)]
    return ['docker', 'exec', session['container_id']] + command \
        if in_container else command


def remote_operation(
        host, session, run_id, action, value=None, ptf_container=True):
    result = container_runtime.command(
        host, _argv(session, run_id, action, value, ptf_container),
        '{} artifact {}'.format(
            'container' if ptf_container else 'host', action))
    if action == 'export':
        return None
    try:
        return json.loads(result.get('stdout', ''))
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            'artifact {} returned invalid JSON'.format(action)) from error


def create_run(host, session, run_id):
    remote_operation(host, session, run_id, 'create', None, ptf_container=False)
    try:
        remote_operation(host, session, run_id, 'create', None, ptf_container=True)
    except Exception as error:
        try:
            remote_operation(
                host, session, run_id, 'delete', None, ptf_container=False)
        except Exception as rollback_error:
            raise RuntimeError(
                '{}; host rollback failed: {}'.format(
                    error, rollback_error)) from error
        raise


def _shell(host, script):
    result = host.shell(
        cmd='set -o pipefail; ' + script, executable='/bin/bash',
        module_ignore_errors=True)
    if (not isinstance(result, Mapping) or type(result.get('rc')) is not int or
            result['rc'] != 0 or any(result.get(flag) for flag in (
                'failed', 'unreachable', 'skipped'))):
        detail = result.get('stderr') or result.get('msg') \
            if isinstance(result, Mapping) else result
        raise RuntimeError(
            'container-to-host artifact transfer failed: {}'.format(detail))


def transfer_to_host(host, session, run_id, name, digest):
    value = {'name': name, 'sha256': digest}
    source = _argv(session, run_id, 'export', value, True)
    destination = _argv(session, run_id, 'import', value, False)
    _shell(host, '{} | {}'.format(
        ' '.join(shlex.quote(item) for item in source),
        ' '.join(shlex.quote(item) for item in destination)))


def fetch_to_controller(host, session, run_id, name, digest, staging):
    source = session['root'] + '/runs/' + run_id + '/' + name
    with tempfile.TemporaryDirectory(prefix='ranking-fetch-') as temporary:
        result = host.fetch(
            src=source, dest=temporary + '/', flat=True,
            fail_on_missing=True, validate_checksum=True,
            module_ignore_errors=True)
        if (not isinstance(result, Mapping) or
                any(result.get(flag) for flag in (
                    'failed', 'unreachable', 'skipped'))):
            raise RuntimeError('fetch {} failed: {}'.format(name, result))
        fetched = Path(temporary) / name
        if fetched.is_symlink() or not fetched.is_file():
            raise RuntimeError(
                'fetched artifact is missing or unsafe: ' + name)
        payload = fetched.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise RuntimeError(
                'host-to-controller artifact hash differs: ' + name)
        target = Path(staging) / name
        target.write_bytes(payload)
        target.chmod(0o600)


def collect(host, session, run_id, staging):
    manifest = remote_operation(
        host, session, run_id, 'inspect', None, ptf_container=True)
    if not isinstance(manifest, dict) or any(
            not isinstance(name, str) or
            not isinstance(digest, str) or SHA256.fullmatch(digest) is None
            for name, digest in manifest.items()):
        raise RuntimeError('container artifact manifest is invalid')
    for name, digest in manifest.items():
        transfer_to_host(host, session, run_id, name, digest)
        fetch_to_controller(host, session, run_id, name, digest, staging)
    current = remote_operation(
        host, session, run_id, 'inspect', None, ptf_container=True)
    if current != manifest:
        raise RuntimeError('container artifacts changed during collection')
    return manifest


def cleanup(host, session, run_id):
    errors = []
    for in_container in (True, False):
        try:
            remote_operation(host, session, run_id, 'delete', None,
                             ptf_container=in_container)
        except Exception as error:
            errors.append(str(error))
    if errors:
        raise RuntimeError(
            'remote artifact cleanup failed: ' + '; '.join(errors))
