"""Build PTF requests and classify the runner's terminal protocol."""

import json
import keyword
import math
from pathlib import Path, PurePosixPath
import re

from tests.ranking.common.artifact_contract import extract_console
from tests.ranking.common.case_selection import validate_case_name


ENV_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')
PARAMETER_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
MAX_LITERAL_DEPTH = 64
FIELDS = frozenset(('phase', 'argv', 'timeout_s', 'rc', 'timed_out',
                    'process_exited'))


def _is_literal(value, active=None, depth=0):
    value_type = type(value)
    if value_type in (str, int, bool, type(None)):
        return True
    if value_type is float:
        return math.isfinite(value)
    if value_type not in (list, tuple, dict) or depth >= MAX_LITERAL_DEPTH:
        return False
    if active is None:
        active = set()
    identity = id(value)
    if identity in active:
        return False
    active.add(identity)
    try:
        if value_type is dict:
            return all(_is_literal(key, active, depth + 1) and
                       _is_literal(item, active, depth + 1)
                       for key, item in value.items())
        return all(_is_literal(item, active, depth + 1) for item in value)
    finally:
        active.remove(identity)


def serialize_test_params(params):
    """Serialize PTF test params as safe Python literals."""
    if not isinstance(params, dict):
        raise ValueError('test_params must be an object')
    for name, value in params.items():
        if (not isinstance(name, str) or not PARAMETER_NAME.fullmatch(name)
                or keyword.iskeyword(name) or name.startswith('__')):
            raise ValueError('invalid PTF parameter name: {!r}'.format(name))
        if not _is_literal(value):
            raise ValueError(
                'test_params value for {!r} must be a finite Python literal'
                .format(name))
    return ';'.join(
        '{}={!r}'.format(name, params[name]) for name in sorted(params))


def _path(value, field):
    if (not isinstance(value, str) or not value.startswith('/') or
            str(PurePosixPath(value)) != value or '\x00' in value):
        raise ValueError('{} must be an absolute canonical path'.format(field))
    return value


def build_request(config, session, case, run_dir):
    """Translate generic Run inputs into one container-runner request."""
    validate_case_name(case)
    executable = _path(config.get('ptf_executable'), 'ptf_executable')
    case_dir = _path(config.get('ptf_case_dir'), 'ptf_case_dir')
    workdir = _path(config.get('ptf_workdir'), 'ptf_workdir')
    collector_dir = _path(config.get('collector_dir'), 'collector_dir')
    run_dir = _path(run_dir, 'run_dir')
    arguments = config.get('ptf_arguments')
    if (not isinstance(arguments, list) or any(
            not isinstance(item, str) or not item or '\x00' in item
            for item in arguments)):
        raise ValueError('ptf_arguments must contain command arguments')
    interfaces = config.get('interface_args', [])
    if (not isinstance(interfaces, list) or any(
            not isinstance(item, str) or not item or '\x00' in item
            for item in interfaces)):
        raise ValueError('interface_args must contain command arguments')
    timeout = config.get('timeout_s')
    if type(timeout) is not int or timeout <= 0:
        raise ValueError('timeout_s must be a positive integer')
    environment = config.get('env', {})
    if (not isinstance(environment, dict) or any(
            not isinstance(key, str) or ENV_NAME.fullmatch(key) is None or
            not isinstance(value, str) or '\x00' in value
            for key, value in environment.items())):
        raise ValueError('env must contain literal environment strings')
    environment = dict(environment)
    binding = _path(session.get('binding_root'), 'binding_root')
    paths = [binding]
    if environment.get('PYTHONPATH') and environment['PYTHONPATH'] != binding:
        paths.append(environment['PYTHONPATH'])
    environment['PYTHONPATH'] = ':'.join(paths)

    argv = [executable, '--test-dir', case_dir, case]
    argv.extend(interfaces)
    argv.extend(arguments)
    test_params = serialize_test_params(config.get('test_params', {}))
    if test_params:
        argv.extend(['--test-params', test_params])
    collector = case.replace('.', '_') + '.json'
    return {
        'argv': argv,
        'env': environment,
        'cwd': workdir,
        'run_dir': run_dir,
        'timeout_s': timeout,
        'container_id': session['container_id'],
        'collector_source': collector_dir + '/' + collector,
    }


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key: ' + key)
        value[key] = item
    return value


def _constant(value):
    raise ValueError('invalid JSON constant: ' + value)


def parse(value):
    """Parse strict runner outcome JSON and validate its terminal fields."""
    if isinstance(value, Path):
        value = value.read_text(encoding='utf-8')
    try:
        result = json.loads(value, object_pairs_hook=_unique,
                            parse_constant=_constant)
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError('outcome is not valid strict JSON') from error
    allowed = FIELDS | {'error', 'log_error', 'container_id',
                        'internal_log_sha256', 'console_log_bytes'}
    if (not isinstance(result, dict) or not FIELDS.issubset(result) or
            set(result).difference(allowed) or result['phase'] != 'ptf' or
            not isinstance(result['argv'], list) or not result['argv'] or
            any(not isinstance(item, str) for item in result['argv']) or
            type(result['timeout_s']) is not int or result['timeout_s'] <= 0 or
            type(result['timed_out']) is not bool or
            type(result['process_exited']) is not bool or
            type(result['rc']) is not int):
        raise ValueError('outcome fields are invalid')
    return result


def console_text(text):
    return extract_console(text)


def classify(result, log_text):
    """Return passed, failed, skipped, or infrastructure."""
    if (not result['process_exited'] or result.get('error') or
            result.get('log_error')):
        return 'infrastructure'
    if result['timed_out'] or result['rc'] == 124:
        return 'failed'
    logs = console_text(log_text)
    if re.search(r'(?m)^FAILED[^\r\n]*', logs):
        return 'failed'
    summaries = re.findall(r'(?m)^OK(?: \(([^)\r\n]*)\))?[ \t]*\r?$', logs)
    skipped = re.search(r'(?:^|, )skipped=(\d+)(?=, |$)', summaries[-1]) \
        if summaries else None
    if skipped is None:
        values = list(re.finditer(
            r'(?m)^Skipped (\d+) tests?[ \t]*\r?$', logs))
        skipped = values[-1] if values else None
    if result['rc'] == 0 and skipped is not None and int(skipped.group(1)) > 0:
        return 'skipped'
    return 'passed' if result['rc'] == 0 else 'failed'
