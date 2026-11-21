"""Generate the case-runtime attribute map from a concrete sai_adapter.py."""

import argparse
import json
import os
from pathlib import Path
import re
import tempfile


DEFAULT_OUTPUT = Path(__file__).resolve().parent / 'ptf' / 'attr_map.json'

OP_BY_PREFIX = {
    'create': 'create',
    'set': 'set',
    'get': 'read',
    'flush': 'create',
}

FUNC_RE = re.compile(r'^def (sai_thrift_\w+)\(')
GUARD_RE = re.compile(r'^\s+if (\w+) is not None:')
VALUE_RE = re.compile(r'sai_thrift_attribute_value_t\(\s*(\w+)\s*=')
ATTR_RE = re.compile(r'\bid=(SAI_[A-Z0-9_]+)')
SIGNATURE_RE = re.compile(r'^def (sai_thrift_\w+)\(([^)]*)\)', re.M | re.S)


def parse_signatures(text):
    """Return adapter parameters in declaration order with defaults removed."""
    result = {}
    for match in SIGNATURE_RE.finditer(text):
        result[match.group(1)] = [
            parameter.split('=')[0].strip()
            for parameter in match.group(2).split(',') if parameter.strip()
        ]
    return result


def classify_op(function_name):
    match = re.match(r'sai_thrift_(?:bulk_)?(\w+?)_', function_name)
    return OP_BY_PREFIX.get(match.group(1)) if match else None


def build_map(lines):
    """Scan adapter lines into ``function|kwarg`` attribute mappings."""
    result = {}
    order = {}
    state = {'func': None, 'guard': None, 'union': None, 'attr': None}

    def emit():
        function = state['func']
        argument = state['guard']
        attribute = state['attr']
        if function and argument and attribute:
            operation = classify_op(function)
            if operation:
                position = order.get(function, 0)
                result['{}|{}'.format(function, argument)] = {
                    'attr': attribute,
                    'union': state['union'],
                    'order': position,
                    'op': operation,
                }
                order[function] = position + 1
        state['guard'] = state['union'] = state['attr'] = None

    for line in lines:
        match = FUNC_RE.match(line)
        if match:
            emit()
            state['func'] = match.group(1)
            continue
        if state['func'] is None:
            continue
        match = GUARD_RE.match(line)
        if match:
            emit()
            state['guard'] = match.group(1)
            continue
        if state['guard'] is None:
            continue
        value_match = VALUE_RE.search(line)
        if value_match and state['union'] is None:
            state['union'] = value_match.group(1)
        attribute_match = ATTR_RE.search(line)
        if attribute_match and state['attr'] is None:
            state['attr'] = attribute_match.group(1)
    emit()
    return result


def _atomic_json(path, value):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(
        prefix='.{}.'.format(path.name), dir=str(path.parent), text=True)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            descriptor = None
            json.dump(value, output, indent=2, sort_keys=True)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def generate(adapter, output=DEFAULT_OUTPUT):
    adapter = Path(adapter)
    if not adapter.is_file() or adapter.is_symlink():
        raise ValueError('--adapter is not a regular file: {}'.format(adapter))
    try:
        text = adapter.read_text(encoding='utf-8', errors='strict')
    except (OSError, UnicodeError) as error:
        raise ValueError('cannot read adapter {}: {}'.format(adapter, error)) from error
    entries = build_map(text.splitlines())
    if not entries:
        raise ValueError('adapter contains no attribute mappings')
    functions = {key.split('|', 1)[0] for key in entries}
    signatures = {
        function: parameters
        for function, parameters in parse_signatures(text).items()
        if function in functions
    }
    missing = sorted(functions.difference(signatures))
    if missing:
        raise ValueError(
            'adapter mappings lack function signatures: {}'.format(
                ', '.join(missing)))
    envelope = {
        'schema_version': 1,
        'entries': entries,
        'signatures': signatures,
    }
    _atomic_json(output, envelope)
    return envelope


def build_parser():
    parser = argparse.ArgumentParser(
        description='Generate tests/ranking/cases/ptf/attr_map.json.')
    parser.add_argument('--adapter', required=True, type=Path,
                        help='generated sai_adapter.py used by the test binding')
    return parser


def main(argv=None):
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        envelope = generate(arguments.adapter, DEFAULT_OUTPUT)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print('generated {} mappings for {} functions in {}'.format(
        len(envelope['entries']), len(envelope['signatures']), DEFAULT_OUTPUT))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
