#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate the value-level SAI capability skeleton report denominator."""
import argparse
import collections
import json
import os
import sys
from pathlib import Path

try:
    from .parse_sai_headers import (EXCLUDED_ATTR_OPS, EXCLUDED_ATTR_PREFIXES,
                                    classify_shape, parse_header)
except ImportError:
    from parse_sai_headers import (EXCLUDED_ATTR_OPS, EXCLUDED_ATTR_PREFIXES,
                                   classify_shape, parse_header)


SCHEMA_VERSION = 2
OPS = ('create', 'set', 'read')
# Header metadata uses SAI's `get`; reports call the same operation `read`.
OP_TO_FLAG_KEY = {'create': 'create', 'set': 'set', 'read': 'get'}
# Only finite header-declared domains expand into value-level denominator rows.
VALUED_SHAPES = frozenset({'bool', 'enum_scalar', 'enum_list', 'enum_nested'})
BOOL_VALUES = ('true', 'false')


def dedup_dirs(dirs):
    """Normalize and order-preserving-deduplicate directory arguments."""
    out = []
    for directory in dirs or ():
        key = os.path.normpath(str(directory))
        if key not in out:
            out.append(key)
    return out


def header_paths(dirs):
    for directory in dirs:
        for path in sorted(Path(directory).iterdir()):
            if path.suffix == '.h':
                yield path


def excluded_ops(attr):
    """Return operations excluded from the denominator for an attribute."""
    if attr.startswith(EXCLUDED_ATTR_PREFIXES):
        return frozenset(OPS)
    for prefix, operations in EXCLUDED_ATTR_OPS.items():
        if attr.startswith(prefix):
            return operations
    return frozenset()


def value_domain(shape, enum_type, enums):
    if shape == 'bool':
        return BOOL_VALUES
    if enum_type:
        members = enums.get(enum_type) or {}
        return tuple(members[key] for key in sorted(members, key=int))
    return ()


def build_cells(attrs, enums):
    """Expand the attribute database into capability cells and statistics."""
    cells = []
    stats = collections.Counter()
    for attribute in attrs:
        attr = attribute['attr']
        shape, enum_type = classify_shape(attribute['type'], enums)
        values = value_domain(shape, enum_type, enums)
        if shape in VALUED_SHAPES and not values:
            print('warning: %s (@type %s) has no expandable value, keeping it '
                  'at attr level' % (attr, attribute['type']), file=sys.stderr)
            stats['empty_value_domain'] += 1
        skip = excluded_ops(attr)
        module = Path(attribute['header']).stem
        for operation in OPS:
            applicable = bool(
                attribute['applicable'].get(OP_TO_FLAG_KEY[operation]))
            if not applicable:
                continue
            expand = (operation != 'read' and shape in VALUED_SHAPES and
                      values)
            if operation in skip:
                stats['excluded_cells'] += len(values) if expand else 1
                continue
            for value in (values if expand else (None,)):
                cells.append({'module': module,
                              'attr': attr,
                              'op': operation,
                              'value': value,
                              'enum_type': enum_type,
                              'shape': shape,
                              'applicable': applicable})
            stats['shape:' + shape] += len(values) if expand else 1
    return cells, stats


def generate_skeleton(inc, experimental, enum_values, out):
    attr_dirs = dedup_dirs(inc)
    enum_dirs = dedup_dirs(attr_dirs + dedup_dirs(experimental))
    bad = [directory for directory in attr_dirs
           if not Path(directory).is_dir()]
    for directory in bad:
        print("error: '%s' is not a directory (expected a SAI header tree "
              "containing sai*.h)" % directory, file=sys.stderr)
    if bad:
        return 2

    with Path(enum_values).open(encoding='utf-8') as enum_file:
        enums = json.load(enum_file)
    attrs = []
    for path in header_paths(attr_dirs):
        got, _aliases = parse_header(path)
        attrs.extend(got)

    if not attrs:
        print("error: no SAI attrs found in %s -- does --inc point at the SAI "
              "'inc' tree containing sai*.h?"
              % ', '.join("'%s'" % directory for directory in attr_dirs),
              file=sys.stderr)
        return 1

    cells, stats = build_cells(attrs, enums)
    skeleton = {'schema_version': SCHEMA_VERSION,
                'denominator': len(cells),
                'attr_dirs': attr_dirs,
                'enum_dirs': enum_dirs,
                'attr_count': len(attrs),
                'enum_count': len(enums),
                'excluded_cell_count': stats['excluded_cells'],
                'cells': cells}
    with Path(out).open('w', encoding='utf-8') as output_file:
        json.dump(skeleton, output_file, indent=1)

    shapes = collections.Counter(cell['shape'] for cell in cells)
    print('%d attrs + %d value enums -> %d cells (denominator) -> %s'
          % (len(attrs), len(enums), len(cells), out))
    print('per shape: ' + ', '.join('%s(%d)' % item
                                    for item in sorted(shapes.items())))
    print('excluded from denominator: %d cell(s) (%s prefixes, %s)'
          % (stats['excluded_cells'], ', '.join(EXCLUDED_ATTR_PREFIXES),
             ', '.join('%s%s' % (prefix, sorted(operations))
                       for prefix, operations in
                       sorted(EXCLUDED_ATTR_OPS.items()))))
    return 0


def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inc', action='append', required=True, type=Path,
                        help='standard SAI header dir defining the attr universe '
                             '(repeatable)')
    parser.add_argument('--experimental', action='append', default=[],
                        type=Path,
                        help='extra header dir scanned for value enums only')
    parser.add_argument('--enum-values', required=True, type=Path,
                        help='gen_enum_values.py output')
    parser.add_argument('--out', required=True, type=Path,
                        help='output skeleton JSON')
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return generate_skeleton(args.inc, args.experimental, args.enum_values,
                             args.out)


if __name__ == '__main__':
    sys.exit(main())
