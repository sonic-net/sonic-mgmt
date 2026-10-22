import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile

from tests.ranking.common.case_selection import (
    PRIORITIES, load_json, validate_case_name, validate_manifest,
    validate_source_identity,
)


def build_manifest(test_names, source_identity, priorities) -> dict:
    validate_source_identity(source_identity)
    if not isinstance(priorities, dict):
        raise ValueError('priorities must be an object')
    for case_name, priority in priorities.items():
        validate_case_name(case_name)
        if priority not in PRIORITIES:
            raise ValueError('invalid priority for case: {}'.format(case_name))
    if not isinstance(test_names, (list, tuple)) or not test_names:
        raise ValueError('test_names must be a non-empty sequence')
    for name in test_names:
        validate_case_name(name)
    if len(test_names) != len(set(test_names)):
        raise ValueError('duplicate test case')
    unknown_priorities = sorted(set(priorities).difference(test_names))
    if unknown_priorities:
        raise ValueError(
            'unknown priority case: {}'.format(', '.join(unknown_priorities)))
    modules = {}
    for name in sorted(test_names):
        module, case = name.split('.')
        entry = modules.setdefault(module, {'cases': {}})
        entry['cases'][case] = {'priority': priorities.get(name, 'P2')}
    manifest = {
        'schema_version': 2,
        'source_identity': deepcopy(source_identity),
        'modules': modules,
    }
    validate_manifest(manifest)
    return manifest


def parse_test_names(lines) -> list[str]:
    names = []
    seen = set()
    for raw_line in lines:
        name = raw_line.strip()
        if not name or any(char.isspace() for char in name) or '.' not in name:
            continue
        validate_case_name(name)
        if name in seen:
            raise ValueError('duplicate test case: {}'.format(name))
        seen.add(name)
        names.append(name)
    if not names:
        raise ValueError('no test names discovered')
    return names


def parse_priority(value):
    if not isinstance(value, str) or value.count('=') != 1:
        raise ValueError('priority must use MODULE.CASE=LEVEL')
    case_name, priority = value.split('=')
    validate_case_name(case_name)
    if priority not in PRIORITIES:
        raise ValueError('invalid priority for case: {}'.format(case_name))
    return case_name, priority


def parse_priorities(values) -> dict:
    priorities = {}
    for value in values:
        case_name, priority = parse_priority(value)
        if case_name in priorities:
            raise ValueError(
                'duplicate priority for case: {}'.format(case_name))
        priorities[case_name] = priority
    return priorities


def write_manifest(test_names, source_identity, priorities, destination):
    manifest = build_manifest(test_names, source_identity, priorities)
    destination = Path(destination)
    content = json.dumps(manifest, indent=2, sort_keys=True) + '\n'
    descriptor, temporary = tempfile.mkstemp(
        prefix='.{}.'.format(destination.name), dir=str(destination.parent), text=True,
    )
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            descriptor = None
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
        os.replace(temporary, destination)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return manifest


def _argument_parser():
    parser = argparse.ArgumentParser(
        description='Generate a Ranking manifest from PTF --list-test-names output.',
    )
    parser.add_argument('--input', default='-', metavar='PATH',
                        help='PTF output file, or - for stdin (default)')
    parser.add_argument('--source-identity', required=True, metavar='JSON')
    parser.add_argument(
        '--priority', action='append', default=[], metavar='MODULE.CASE=LEVEL')
    parser.add_argument('--output', required=True, metavar='JSON')
    return parser


def main(argv=None, stdin=None):
    parser = _argument_parser()
    arguments = parser.parse_args(argv)
    try:
        priorities = parse_priorities(arguments.priority)
        source_identity = load_json(arguments.source_identity, 'source identity')
        if arguments.input == '-':
            test_names = parse_test_names(sys.stdin if stdin is None else stdin)
        else:
            with open(arguments.input, encoding='utf-8') as discovered:
                test_names = parse_test_names(discovered)
        write_manifest(test_names, source_identity, priorities, arguments.output)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
