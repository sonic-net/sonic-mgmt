#!/usr/bin/env python3
"""Generate the complete metadata package consumed by Ranking Report."""

import argparse
import json
from pathlib import Path
import sys
import tempfile

try:
    from .gen_enum_values import generate_enum_values
    from .gen_skeleton import generate_skeleton
except ImportError:
    from gen_enum_values import generate_enum_values
    from gen_skeleton import generate_skeleton


REPORT_ROOT = Path(__file__).resolve().parents[1]
RANKING_ROOT = REPORT_ROOT.parent
METADATA_ROOT = REPORT_ROOT / 'metadata'
CASE_SPEC_REGISTRY = RANKING_ROOT / 'cases' / 'ptf' / 'spec_registry.json'
METADATA_FILES = ('enum_values.json', 'skeleton.json', 'spec_registry.json')
KNOWN_METRIC_TYPES = frozenset(
    ('throughput', 'latency', 'counter', 'scale', 'fill_rate'))
REQUIRED_METRIC_FIELDS = {
    'description': str,
    'direction': str,
    'metric_type': str,
    'operations': list,
    'unit': str,
}


def validate_inputs(headers, experimental_headers, case_registry):
    headers = Path(headers)
    experimental = [Path(directory) for directory in experimental_headers]
    case_registry = Path(case_registry)
    if not headers.is_dir() or headers.is_symlink():
        raise ValueError('--headers is not a directory: %s' % headers)
    if not any(path.suffix == '.h' for path in headers.iterdir()):
        raise ValueError('--headers contains no SAI headers: %s' % headers)
    for directory in experimental:
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError(
                '--experimental-headers is not a directory: %s' % directory)
    if not case_registry.is_file() or case_registry.is_symlink():
        raise ValueError(
            'case spec registry is not a regular file: %s' % case_registry)


def _load_case_registry(path):
    try:
        with Path(path).open(encoding='utf-8') as source:
            value = json.load(source)
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError('cannot load case spec registry: %s' % error) from error
    if not isinstance(value, dict):
        raise ValueError('case spec registry is not an object')
    return value


def build_report_registry(case_registry):
    """Select reportable metric definitions from the case-side registry."""
    report = {}
    for name, definition in case_registry.items():
        if name.startswith('_'):
            continue
        if not isinstance(definition, dict):
            raise ValueError('case spec registry entry is not an object: %s' % name)
        if definition.get('result_type') == 'capability':
            continue
        metric_type = definition.get('metric_type')
        if metric_type not in KNOWN_METRIC_TYPES:
            raise ValueError(
                'case spec registry %s has unknown metric_type %r'
                % (name, metric_type))
        for field, expected_type in REQUIRED_METRIC_FIELDS.items():
            if not isinstance(definition.get(field), expected_type):
                raise ValueError(
                    'case spec registry %s.%s has the wrong type'
                    % (name, field))
        included = definition.get('include_in_report', True)
        if type(included) is not bool:
            raise ValueError(
                'case spec registry %s.include_in_report has the wrong type'
                % name)
        display_name = definition.get('display_name')
        if (included and
                (not isinstance(display_name, str) or not display_name.strip())):
            raise ValueError(
                'case spec registry %s.display_name has the wrong type'
                % name)
        if not all(isinstance(operation, str)
                   for operation in definition['operations']):
            raise ValueError(
                'case spec registry %s.operations must contain strings' % name)
        report[name] = definition
    if not report:
        raise ValueError('case spec registry contains no reportable metrics')
    return report


def validate_capability_coverage(case_registry, skeleton_path):
    """Require every generated capability attribute to exist case-side."""
    capability_names = {
        name for name, definition in case_registry.items()
        if (not name.startswith('_') and isinstance(definition, dict)
            and definition.get('result_type') == 'capability')
    }
    try:
        with Path(skeleton_path).open(encoding='utf-8') as source:
            skeleton = json.load(source)
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError('cannot load generated capability skeleton: %s' % error) from error
    generated_names = {
        cell.get('attr') for cell in skeleton.get('cells', [])
        if isinstance(cell, dict) and isinstance(cell.get('attr'), str)
    }
    missing = sorted(generated_names.difference(capability_names))
    if missing:
        raise ValueError(
            'case spec registry is missing capability definitions: %s'
            % ', '.join(missing))


def _write_json(path, value):
    with Path(path).open('w', encoding='utf-8') as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write('\n')


def validate_metadata(directory):
    directory = Path(directory)
    paths = {name: directory / name for name in METADATA_FILES}
    with paths['enum_values.json'].open(encoding='utf-8') as enum_file:
        enums = json.load(enum_file)
    with paths['skeleton.json'].open(encoding='utf-8') as skeleton_file:
        skeleton = json.load(skeleton_file)
    with paths['spec_registry.json'].open(encoding='utf-8') as registry_file:
        registry = json.load(registry_file)

    if not isinstance(enums, dict):
        raise ValueError('enum_values.json is not an object')
    if (not isinstance(skeleton, dict) or
            not isinstance(skeleton.get('cells'), list) or
            skeleton.get('denominator') != len(skeleton['cells'])):
        raise ValueError('skeleton.json has an invalid cell set')
    if not isinstance(registry, dict) or not registry:
        raise ValueError('spec_registry.json is not a non-empty object')
    return paths


def generate(headers, experimental_headers, case_registry, out_dir):
    validate_inputs(headers, experimental_headers, case_registry)
    headers = Path(headers)
    experimental = [Path(directory) for directory in experimental_headers]
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    case_definitions = _load_case_registry(case_registry)
    report_registry = build_report_registry(case_definitions)

    with tempfile.TemporaryDirectory(
            prefix='.ranking-metadata-', dir=str(out_dir)) as staging_name:
        staging = Path(staging_name)
        enum_values = staging / 'enum_values.json'
        skeleton = staging / 'skeleton.json'
        registry = staging / 'spec_registry.json'

        generate_enum_values(headers, experimental, enum_values)
        result = generate_skeleton([headers], enum_values, skeleton)
        if result:
            raise RuntimeError(
                'capability skeleton generation failed with exit status %d'
                % result)
        validate_capability_coverage(case_definitions, skeleton)
        _write_json(registry, report_registry)
        paths = validate_metadata(staging)
        for name in METADATA_FILES:
            paths[name].replace(out_dir / name)


def build_parser():
    parser = argparse.ArgumentParser(
        description='Generate metadata in tests/ranking/report/metadata.')
    parser.add_argument('--headers', required=True, type=Path,
                        help='standard SAI header directory, for example SAI/inc')
    parser.add_argument('--experimental-headers', action='append', default=[],
                        type=Path,
                        help='optional extension header directory (repeatable)')
    return parser


def main(argv=None):
    arguments = build_parser().parse_args(argv)
    try:
        generate(arguments.headers, arguments.experimental_headers,
                 CASE_SPEC_REGISTRY, METADATA_ROOT)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print('error: %s' % error, file=sys.stderr)
        return 2
    print('read case specs from %s' % CASE_SPEC_REGISTRY)
    print('generated %s in %s' % (', '.join(METADATA_FILES), METADATA_ROOT))
    return 0


if __name__ == '__main__':
    sys.exit(main())
