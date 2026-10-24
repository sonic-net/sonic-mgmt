import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path


PHASE = 'ptf'
OUTCOME_FILE = 'outcome.json'
STDOUT_LOG = 'stdout.log'
STDERR_LOG = 'stderr.log'
GRACE_SECONDS = 5
TIMEOUT_RC = 124
SPAWN_ERROR_RC = 127
REQUEST_FIELDS = ('argv', 'env', 'cwd', 'run_dir', 'timeout_s')
OUTCOME_FIELDS = frozenset((
    'phase', 'pid', 'group', 'birth', 'argv', 'timeout_s', 'rc', 'timed_out',
    'process_exited',
))
RECOVERY_POLL_SECONDS = 0.1
DISPATCH_GRACE_SECONDS = 4 * GRACE_SECONDS
DOCKER_IO_TIMEOUT_SECONDS = GRACE_SECONDS
ERROR_RC = 1
CONTAINER_ID_PATTERN = re.compile(r'[0-9a-f]{64}')
ENV_PATTERN = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


def _proc_stat(pid):
    with open('/proc/{0}/stat'.format(pid), 'r', encoding='utf-8') as handle:
        return handle.read()


def _proc_scan():
    records = []
    with os.scandir('/proc') as entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            try:
                records.append((int(entry.name), _proc_stat(int(entry.name))))
            except (FileNotFoundError, ProcessLookupError):
                continue
    return records


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
    if fields[2] != str(pid) or fields[3] != str(pid):
        return None
    return fields[19]


def _write_outcome(run_path, outcome):
    path = run_path / OUTCOME_FILE
    temporary = run_path / ('.{}-{}'.format(OUTCOME_FILE, uuid.uuid4().hex))
    text = json.dumps(outcome, sort_keys=True, indent=2, ensure_ascii=True,
                      allow_nan=False) + '\n'
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(run_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def run_ptf(argv, *, env, cwd, run_dir, timeout_s, container_id=None,
            birth_reader=None, proc_scanner=None, group_kill=None, clock=None,
            sleeper=None) -> dict:
    run_path = Path(run_dir)
    run_path.mkdir(mode=0o700, parents=True, exist_ok=False)
    arguments = list(argv)
    outcome = {
        'phase': PHASE, 'pid': None, 'group': None, 'birth': None,
        'argv': arguments, 'timeout_s': timeout_s, 'rc': None,
        'timed_out': False, 'process_exited': False,
    }
    if container_id is not None:
        _container_id(container_id)
        outcome['container_id'] = container_id
    try:
        with open(run_path / STDOUT_LOG, 'wb') as stdout_log, \
                open(run_path / STDERR_LOG, 'wb') as stderr_log:
            process = subprocess.Popen(
                arguments, shell=False, start_new_session=True, cwd=cwd, env=env,
                stdout=stdout_log, stderr=stderr_log)
    except OSError as error:
        outcome.update(rc=SPAWN_ERROR_RC, process_exited=True, error=str(error))
        _write_outcome(run_path, outcome)
        return outcome
    pid = process.pid
    birth = process_birth(pid, reader=birth_reader)
    outcome.update(pid=pid, group=pid, birth=birth)
    try:
        _write_outcome(run_path, outcome)
        try:
            outcome['rc'] = process.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            outcome.update(timed_out=True, rc=TIMEOUT_RC)
        except OSError as error:
            _add_error(outcome, 'could not wait for PTF: {}'.format(error))
        _write_outcome(run_path, outcome)
    except OSError as error:
        _add_error(outcome, 'could not persist PTF outcome: {}'.format(error))
    finally:
        try:
            _cleanup_session(pid, birth, proc_scanner=proc_scanner,
                             group_kill=group_kill, clock=clock, sleeper=sleeper,
                             reaper=process.poll)
            process.wait(timeout=GRACE_SECONDS)
            outcome['process_exited'] = True
            if outcome['rc'] is None:
                outcome['rc'] = process.returncode
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            _add_error(outcome, str(error))
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
            raise ValueError('duplicate JSON key: {}'.format(key))
        result[key] = item
    return result


def _invalid_constant(value):
    raise ValueError('invalid JSON constant: {}'.format(value))


def _container_id(value):
    if not isinstance(value, str) or CONTAINER_ID_PATTERN.fullmatch(value) is None:
        raise ValueError('container_id must be an immutable full container ID')
    return value


def _add_error(outcome, message):
    outcome['error'] = '{}; {}'.format(outcome['error'], message) if \
        outcome.get('error') else message


def _validate_outcome(value):
    if not isinstance(value, dict) or not OUTCOME_FIELDS.issubset(value) or \
            set(value).difference(OUTCOME_FIELDS | {'error', 'container_id'}):
        raise ValueError('outcome must declare the runner outcome fields exactly')
    if value['phase'] != PHASE:
        raise ValueError('outcome phase is invalid')
    if (not isinstance(value['argv'], list) or not value['argv'] or
            any(not isinstance(argument, str) for argument in value['argv'])):
        raise ValueError('outcome argv must be a non-empty string array')
    if type(value['timeout_s']) is not int or value['timeout_s'] <= 0:
        raise ValueError('outcome timeout_s must be a positive integer')
    for field in ('timed_out', 'process_exited'):
        if type(value[field]) is not bool:
            raise ValueError('outcome {} must be a boolean'.format(field))
    if type(value['rc']) is not int and not (
            value['rc'] is None and not value['process_exited']):
        raise ValueError('outcome rc must be numeric unless exit is unconfirmed')
    if 'container_id' in value:
        _container_id(value['container_id'])
    identity = (value['pid'], value['group'], value['birth'])
    if identity == (None, None, None):
        if value['process_exited']:
            if value['rc'] != SPAWN_ERROR_RC or not value.get('error'):
                raise ValueError('identity-free exit proof is valid only for a spawn error')
        elif not ('container_id' in value and value.get('error')):
            raise ValueError('unconfirmed outcome must carry identity or dispatch error')
    elif (type(value['pid']) is not int or value['pid'] <= 0 or
          type(value['group']) is not int or value['group'] != value['pid'] or
          (value['process_exited'] and value['birth'] is None) or
          (value['birth'] is not None and
           (not isinstance(value['birth'], str) or not value['birth']))):
        raise ValueError('outcome process identity is invalid')
    if 'error' in value and (not isinstance(value['error'], str) or not value['error']):
        raise ValueError('outcome error must be a non-empty string')
    return value


def parse_outcome(text):
    if not isinstance(text, str):
        raise ValueError('outcome must be UTF-8 text')
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates,
                           parse_constant=_invalid_constant)
    except ValueError as error:
        raise ValueError('outcome is not valid strict JSON: {}'.format(error)) from error
    return _validate_outcome(value)


def load_outcome(path):
    try:
        text = Path(path).read_text(encoding='utf-8')
    except (OSError, UnicodeError) as error:
        raise ValueError('outcome cannot be read: {}'.format(error)) from error
    return parse_outcome(text)


def _scan_records(scanner):
    try:
        records = scanner()
    except OSError as error:
        raise ValueError('could not scan process groups: {}'.format(error)) from error
    if isinstance(records, dict):
        records = records.items()
    try:
        records = list(records)
    except TypeError as error:
        raise ValueError('process scanner returned invalid records') from error
    for record in records:
        if not isinstance(record, (tuple, list)) or len(record) != 2:
            raise ValueError('process scanner returned invalid records')
        pid, text = record
        if type(pid) is not int or pid <= 0 or not isinstance(text, str):
            raise ValueError('process scanner returned invalid records')
    return records


def _stat_pid(text):
    opening = text.find('(')
    if opening <= 0:
        return None
    value = text[:opening].strip()
    try:
        pid = int(value)
    except ValueError:
        return None
    return pid if pid > 0 else None


def _session_members(group, birth, scanner):
    if not isinstance(birth, str) or not birth:
        raise ValueError('recorded process birth is missing')
    members = []
    seen = set()
    for pid, text in _scan_records(scanner):
        fields = _parse_stat(text)
        if fields is None or _stat_pid(text) != pid or pid in seen:
            raise ValueError('process scan contains unreadable or ambiguous identity')
        seen.add(pid)
        try:
            process_group = int(fields[2])
            session = int(fields[3])
        except ValueError as error:
            raise ValueError('process scan contains invalid session identity') from error
        if not fields[19]:
            raise ValueError('process scan contains missing birth identity')
        if pid == group and (fields[19] != birth or process_group != group or
                             session != group):
            raise ValueError('recorded process identity or session is lost or mismatched')
        if process_group == group and session != group:
            raise ValueError('recorded process group belongs to a conflicting session')
        if session == group:
            if process_group <= 0:
                raise ValueError('recorded session contains an invalid process group')
            # A single-threaded zombie has exited and only its parent can reap it; a zombie
            # leader with live threads still counts, so it is signalled like any member.
            if fields[0] in ('Z', 'X') and fields[17] == '1':
                continue
            members.append((pid, fields[19], process_group, session))
    return members


def _observe_group(group, birth, scanner):
    try:
        return 'ours' if _session_members(group, birth, scanner) else 'exited'
    except ValueError:
        return 'lost'


def _signal_session(group, birth, scanner, kill, sig, members):
    for target in sorted({member[2] for member in members}):
        live = _session_members(group, birth, scanner)
        candidates = {member for member in live if member[2] == target}
        if not candidates:
            continue
        if not candidates.intersection(members):
            raise ValueError('signal target identity changed before killpg')
        try:
            kill(target, sig)
        except ProcessLookupError:
            pass
        except OSError as error:
            raise ValueError('could not signal recorded session: {}'.format(error)) from error


def _cleanup_session(group, birth, *, proc_scanner=None, group_kill=None,
                     clock=None, sleeper=None, reaper=None):
    scan = _proc_scan if proc_scanner is None else proc_scanner
    kill = os.killpg if group_kill is None else group_kill
    monotonic = time.monotonic if clock is None else clock
    pause = time.sleep if sleeper is None else sleeper
    for sig in (signal.SIGTERM, signal.SIGKILL):
        deadline = monotonic() + GRACE_SECONDS
        while True:
            if reaper is not None:
                reaper()
            members = _session_members(group, birth, scan)
            if not members:
                return
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            # A child may change pgrp while its session remains ours.
            _signal_session(group, birth, scan, kill, sig, members)
            if reaper is not None:
                reaper()
            if not _session_members(group, birth, scan):
                return
            remaining = deadline - monotonic()
            if remaining > 0:
                pause(min(RECOVERY_POLL_SECONDS, remaining))
    if reaper is not None:
        reaper()
    if _session_members(group, birth, scan):
        raise ValueError('recorded process session survived TERM and KILL')


def recover_outcome(path, *, birth_reader=None, proc_scanner=None, group_kill=None,
                    clock=None, sleeper=None):
    outcome_path = Path(path)
    outcome = load_outcome(outcome_path)
    if outcome['process_exited']:
        return outcome
    if outcome['group'] != outcome['pid'] or outcome['pid'] is None:
        raise ValueError('outcome does not carry a recoverable process identity')
    _cleanup_session(outcome['group'], outcome['birth'], proc_scanner=proc_scanner,
                     group_kill=group_kill, clock=clock, sleeper=sleeper)
    recovered = dict(outcome, process_exited=True)
    if recovered['rc'] is None:
        recovered['rc'] = ERROR_RC
        _add_error(recovered, 'PTF exit status is unavailable after recovery')
    _write_outcome(outcome_path.parent, recovered)
    return recovered


def _load_request(arguments):
    if len(arguments) != 2 or arguments[0] != '--request':
        raise ValueError('usage: ptf_runner --request <request.json|->')
    text = sys.stdin.read() if arguments[1] == '-' else \
        Path(arguments[1]).read_text(encoding='utf-8')
    try:
        request = json.loads(text, object_pairs_hook=_no_duplicates,
                             parse_constant=_invalid_constant)
    except ValueError as error:
        raise ValueError('request is not valid strict JSON: {}'.format(error)) from error
    if not isinstance(request, dict) or set(request).difference(
            set(REQUEST_FIELDS) | {'container_id'}):
        raise ValueError('request must be an object with only runner request fields')
    for field in REQUEST_FIELDS:
        if field not in request:
            raise ValueError('request is missing field: {}'.format(field))
    if (not isinstance(request['argv'], list) or not request['argv'] or
            any(not isinstance(argument, str) or '\x00' in argument
                for argument in request['argv'])):
        raise ValueError('request argv must be a non-empty string array without NUL')
    if (not isinstance(request['env'], dict) or
            any(not isinstance(key, str) or ENV_PATTERN.fullmatch(key) is None or
                not isinstance(value, str) or '\x00' in value
                for key, value in request['env'].items())):
        raise ValueError('request env must map environment names to strings without NUL')
    for field in ('cwd', 'run_dir'):
        path = request[field]
        if (not isinstance(path, str) or not os.path.isabs(path) or
                os.path.normpath(path) != path or '\x00' in path):
            raise ValueError('request {} must be an absolute canonical path'.format(field))
    if type(request['timeout_s']) is not int or request['timeout_s'] <= 0:
        raise ValueError('request timeout_s must be a positive integer')
    if 'container_id' in request:
        _container_id(request['container_id'])
    return request


def _docker_request(request):
    argv = request['argv']
    if os.path.basename(argv[0]) != 'docker':
        return None
    if len(argv) < 4 or argv[1] != 'exec':
        raise ValueError('only strict foreground docker exec PTF requests are supported')
    environment = dict(request['env'])
    index = 2
    while index < len(argv) and argv[index] == '--env':
        if index + 1 >= len(argv) or '=' not in argv[index + 1]:
            raise ValueError('docker exec --env must declare KEY=VALUE')
        key, value = argv[index + 1].split('=', 1)
        if ENV_PATTERN.fullmatch(key) is None or '\x00' in value:
            raise ValueError('docker exec contains an invalid environment assignment')
        environment[key] = value
        index += 2
    if index >= len(argv):
        raise ValueError('docker exec is missing its immutable container ID')
    container_id = _container_id(argv[index])
    command = argv[index + 1:]
    if not command or not command[0] or command[0].startswith('-') or \
            os.path.basename(command[0]) == 'docker':
        raise ValueError('docker exec must contain a direct foreground PTF command')
    if 'container_id' in request and request['container_id'] != container_id:
        raise ValueError('docker exec container provenance differs from request')
    return dict(request, argv=command, env=environment, container_id=container_id)


def _runner_path():
    return os.path.abspath(__file__)


def _matching_outcome(outcome, expected, identity=False):
    for field in ('container_id', 'argv', 'timeout_s'):
        if outcome.get(field) != expected.get(field):
            raise ValueError('container outcome {} differs from dispatch provenance'.format(field))
    if identity and expected['pid'] is not None:
        for field in ('pid', 'group', 'birth'):
            if outcome[field] != expected[field]:
                raise ValueError('recovered container process identity differs from host outcome')
    if identity and expected['rc'] is not None and outcome['rc'] != expected['rc']:
        raise ValueError('recovered container case rc differs from host outcome')


def _copy_container_file(container_id, source, run_path, name):
    temporary = run_path / ('.copy-{}-{}'.format(name, uuid.uuid4().hex))
    try:
        result = subprocess.run(
            ['docker', 'cp', '{}:{}'.format(container_id, source), str(temporary)],
            shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=DOCKER_IO_TIMEOUT_SECONDS)
        if result.returncode != 0:
            raise ValueError('docker cp failed for {}'.format(name))
        if not stat.S_ISREG(os.lstat(temporary).st_mode):
            raise ValueError('docker cp did not produce a regular {}'.format(name))
        return temporary
    except Exception:
        if os.path.lexists(temporary) and not temporary.is_dir():
            temporary.unlink()
        raise


def dispatch_container(request):
    container_id = request['container_id']
    run_path = Path(request['run_dir'])
    run_path.mkdir(mode=0o700, parents=True, exist_ok=False)
    dispatch_error = None
    try:
        result = subprocess.run(
            ['docker', 'exec', '-i', container_id, 'python3', _runner_path(),
             '--request', '-'],
            input=json.dumps(request, sort_keys=True, ensure_ascii=True, allow_nan=False),
            text=True, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=request['timeout_s'] + DISPATCH_GRACE_SECONDS)
        if result.returncode != 0:
            dispatch_error = 'container dispatcher failed: {}'.format(result.stderr.strip())
    except (OSError, subprocess.TimeoutExpired) as error:
        dispatch_error = 'container dispatch is unconfirmed: {}'.format(error)
    outcome = None
    copy_errors = []
    for name in (OUTCOME_FILE, STDOUT_LOG, STDERR_LOG):
        temporary = None
        try:
            temporary = _copy_container_file(
                container_id, str(run_path / name), run_path, name)
            if name == OUTCOME_FILE:
                outcome = load_outcome(temporary)
                _matching_outcome(outcome, request)
            else:
                os.replace(temporary, run_path / name)
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            if name == OUTCOME_FILE:
                outcome = None
            copy_errors.append('{}: {}'.format(name, error))
        finally:
            if temporary is not None and os.path.lexists(temporary):
                temporary.unlink()
    if outcome is None:
        outcome = {
            'phase': PHASE, 'pid': None, 'group': None, 'birth': None,
            'argv': request['argv'], 'timeout_s': request['timeout_s'], 'rc': None,
            'timed_out': False, 'process_exited': False, 'container_id': container_id,
        }
    if copy_errors:
        outcome['process_exited'] = False
        _add_error(outcome, '; '.join(copy_errors))
    if not outcome['process_exited']:
        _add_error(outcome, dispatch_error or 'actual PTF session exit is unconfirmed')
    _write_outcome(run_path, outcome)
    return outcome


def recover_host_outcome(path):
    outcome_path = Path(os.path.abspath(path))
    outcome = load_outcome(outcome_path)
    if 'container_id' not in outcome:
        return recover_outcome(outcome_path)
    if outcome['process_exited']:
        return outcome
    result = subprocess.run(
        ['docker', 'exec', outcome['container_id'], 'python3', _runner_path(),
         '--recover-local-outcome', str(outcome_path)],
        text=True, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=DISPATCH_GRACE_SECONDS)
    if result.returncode != 0:
        raise ValueError('container recovery failed: {}'.format(result.stderr.strip()))
    recovered = parse_outcome(result.stdout)
    _matching_outcome(recovered, outcome, identity=True)
    if not recovered['process_exited']:
        raise ValueError('container recovery did not confirm actual PTF session exit')
    # The first copy may have captured logs while PTF was still writing.
    for name in (STDOUT_LOG, STDERR_LOG):
        temporary = _copy_container_file(
            outcome['container_id'], str(outcome_path.parent / name),
            outcome_path.parent, name)
        try:
            os.replace(temporary, outcome_path.parent / name)
        finally:
            if os.path.lexists(temporary):
                temporary.unlink()
    _write_outcome(outcome_path.parent, recovered)
    return recovered


def main(argv=None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if len(arguments) == 2 and arguments[0] == '--validate-outcome':
            outcome = parse_outcome(sys.stdin.read()) if arguments[1] == '-' else \
                load_outcome(arguments[1])
            code = 0
        elif len(arguments) == 2 and arguments[0] == '--recover-outcome':
            outcome = recover_host_outcome(arguments[1])
            code = 0
        elif len(arguments) == 2 and arguments[0] == '--recover-local-outcome':
            outcome = recover_outcome(arguments[1])
            code = 0
        else:
            request = _load_request(arguments)
            inner = _docker_request(request)
            if inner is not None:
                outcome = dispatch_container(inner)
            else:
                environment = dict(os.environ)
                environment.update(request['env'])
                outcome = run_ptf(
                    request['argv'], env=environment, cwd=request['cwd'],
                    run_dir=request['run_dir'], timeout_s=request['timeout_s'],
                    container_id=request.get('container_id'))
            code = outcome['rc'] if type(outcome['rc']) is int else ERROR_RC
            if not outcome['process_exited'] or outcome.get('error'):
                code = code or ERROR_RC
            if outcome.get('error'):
                print('ptf_runner: {}'.format(outcome['error']), file=sys.stderr)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print('ptf_runner: {}'.format(error), file=sys.stderr)
        return 1
    print(json.dumps(outcome, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return code


if __name__ == '__main__':
    sys.exit(main())
