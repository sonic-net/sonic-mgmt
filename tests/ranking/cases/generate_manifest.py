"""Generate the Ranking case manifest from PTF's test-name listing."""

from __future__ import annotations

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile

from tests.ranking.common.case_selection import (
    PRIORITIES, load_case_manifest, validate_case_name, validate_manifest,
    validate_source_identity,
)


DEFAULT_MANIFEST = Path(__file__).resolve().with_name('manifest.json')


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


def write_manifest(test_names, source_identity, priorities, destination):
    manifest = build_manifest(test_names, source_identity, priorities)
    destination = Path(destination)
    content = json.dumps(manifest, indent=2, sort_keys=True) + '\n'
    descriptor, temporary = tempfile.mkstemp(
        prefix='.{}.'.format(destination.name), dir=str(destination.parent),
        text=True)
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


def discover_test_names(ptf_runner, test_dir) -> list[str]:
    """Run PTF's built-in listing command and return its case names."""
    runner = Path(ptf_runner)
    cases = Path(test_dir)
    if not runner.is_file() or runner.is_symlink():
        raise ValueError('--ptf-runner is not a regular file: {}'.format(runner))
    if not cases.is_dir() or cases.is_symlink():
        raise ValueError('--test-dir is not a directory: {}'.format(cases))
    try:
        result = subprocess.run(
            [str(runner), '--test-dir', str(cases), '--list-test-names'],
            capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError('PTF test listing could not start: {}'.format(error)) from error
    if result.returncode:
        detail = (result.stderr or result.stdout or 'no error output').strip()
        raise ValueError(
            'PTF test listing failed with exit status {}: {}'.format(
                result.returncode, detail))
    return parse_test_names(result.stdout.splitlines())


def _existing_priorities(manifest):
    return {
        '{}.{}'.format(module, case): metadata['priority']
        for module, definition in manifest['modules'].items()
        for case, metadata in definition['cases'].items()
    }


def generate_manifest(test_names, destination=DEFAULT_MANIFEST):
    """Replace the manifest, retaining priorities for cases that still exist."""
    existing = load_case_manifest(destination)
    priorities = _existing_priorities(existing)
    selected = set(test_names)
    retained = {name: priority for name, priority in priorities.items()
                if name in selected}
    return write_manifest(
        test_names, existing['source_identity'], retained, destination)


def build_parser():
    parser = argparse.ArgumentParser(
        description='List PTF cases and generate tests/ranking/cases/manifest.json.')
    parser.add_argument('--ptf-runner', type=Path,
                        help='PTF command, for example SAI/test/ptf/ptf')
    parser.add_argument('--test-dir', type=Path,
                        help='PTF case directory, for example SAI/ptf')
    parser.add_argument(
        '--test-name-list', type=Path,
        help='optional saved --list-test-names output; skips PTF execution')
    return parser


def main(argv=None):
    parser = build_parser()
    arguments = parser.parse_args(argv)
    if (arguments.test_name_list is None and
            (arguments.ptf_runner is None or arguments.test_dir is None)):
        parser.error(
            '--ptf-runner and --test-dir are required unless '
            '--test-name-list is used')
    try:
        if arguments.test_name_list is None:
            names = discover_test_names(arguments.ptf_runner, arguments.test_dir)
        else:
            with arguments.test_name_list.open(encoding='utf-8') as source:
                names = parse_test_names(source)
        manifest = generate_manifest(names, DEFAULT_MANIFEST)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print('generated {} cases in {}'.format(
        sum(len(entry['cases']) for entry in manifest['modules'].values()),
        DEFAULT_MANIFEST))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
