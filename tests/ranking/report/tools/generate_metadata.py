#!/usr/bin/env python3
"""Generate all runtime report metadata from one SAI build."""
import argparse
import json
import sys
import tempfile
from pathlib import Path

try:
    from .gen_enum_values import generate_enum_values
    from .gen_skeleton import generate_skeleton
except ImportError:
    from gen_enum_values import generate_enum_values
    from gen_skeleton import generate_skeleton


METADATA_FILES = ('enum_values.json', 'skeleton.json')


def validate_inputs(args):
    inc = Path(args.inc)
    experimental = [Path(directory) for directory in args.experimental]
    if not inc.is_dir():
        raise ValueError('--inc is not a directory: %s' % inc)
    if not any(path.name.endswith('.h') for path in inc.iterdir()):
        raise ValueError('--inc contains no SAI headers: %s' % inc)
    for directory in experimental:
        if not directory.is_dir():
            raise ValueError('--experimental is not a directory: %s'
                             % directory)


def validate_metadata(directory):
    directory = Path(directory)
    paths = {name: directory / name for name in METADATA_FILES}
    with paths['enum_values.json'].open(encoding='utf-8') as enum_file:
        enums = json.load(enum_file)
    with paths['skeleton.json'].open(encoding='utf-8') as skeleton_file:
        skeleton = json.load(skeleton_file)

    if not isinstance(enums, dict):
        raise ValueError('enum_values.json is not an object')
    if (not isinstance(skeleton, dict) or
            not isinstance(skeleton.get('cells'), list) or
            skeleton.get('denominator') != len(skeleton['cells'])):
        raise ValueError('skeleton.json has an invalid cell set')
    return paths


def generate(args):
    validate_inputs(args)
    inc = Path(args.inc)
    experimental = [Path(directory) for directory in args.experimental]
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix='.ranking-metadata-',
                                     dir=str(out_dir)) as staging_name:
        staging = Path(staging_name)
        enum_values = staging / 'enum_values.json'
        skeleton = staging / 'skeleton.json'

        generate_enum_values(inc, experimental, enum_values)
        result = generate_skeleton([inc], experimental, enum_values, skeleton)
        if result:
            raise RuntimeError('capability skeleton generation failed with '
                               'exit status %d' % result)
        paths = validate_metadata(staging)
        for name in METADATA_FILES:
            paths[name].replace(out_dir / name)


def build_parser():
    parser = argparse.ArgumentParser(
        description='Generate enum values and the capability skeleton.')
    parser.add_argument('--inc', required=True, type=Path,
                        help='SAI header directory')
    parser.add_argument('--experimental', action='append', default=[],
                        type=Path,
                        help='additional SAI header directory (repeatable)')
    parser.add_argument('--out-dir', required=True, type=Path,
                        help='directory for generated report metadata')
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        generate(args)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print('error: %s' % error, file=sys.stderr)
        return 2
    print('generated %s in %s' % (', '.join(METADATA_FILES), args.out_dir))
    return 0


if __name__ == '__main__':
    sys.exit(main())
