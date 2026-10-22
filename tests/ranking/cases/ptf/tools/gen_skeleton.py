#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_skeleton.py - value-level SAI capability skeleton (the report denominator).

Emits the *should-be-tested* set of capability cells (schema_version 2) at mixed
granularity:

* ``@type`` with a finite, header-declared value domain (``bool``, an enum, an
  enum list, an ACL-wrapped enum) expands to one cell **per value** for the
  ``create`` / ``set`` operations -- that is what answers "does this chip
  support SAI_PACKET_ACTION_TRAP?".
* everything else (integers, object ids, addresses, structs, function pointers)
  stays at attr granularity (``value: null``): it has no enumerable domain, and
  picking values by hand would be a manual asset.
* ``read`` never expands: ``get`` is called with a placeholder, so the value
  carries no information.

Vendor-neutral by construction: values come from the headers, never from a
per-chip list.

The value domain comes from gen_enum_values.py, which is the single definition
of what counts as a value -- parsing enums here too let the two disagree, and
any value this skeleton declared but that table could not resolve back to a
name was a permanently unreachable cell.

Usage:
    python3 gen_enum_values.py --inc inc --experimental experimental \
        --out ptf/enum_values.json
    python3 gen_skeleton.py --inc inc [--experimental experimental] \
        --enum-values ptf/enum_values.json --out ptf/skeleton.json
"""
import argparse
import collections
import json
import os
import sys

from parse_sai_headers import (EXCLUDED_ATTR_OPS, EXCLUDED_ATTR_PREFIXES,
                               classify_shape, parse_header)

SCHEMA_VERSION = 2
OPS = ('create', 'set', 'read')
# parse_flags() reports applicability with SAI's API verb 'get'; a cell calls
# the same operation 'read'.
OP_TO_FLAG_KEY = {'create': 'create', 'set': 'set', 'read': 'get'}
# Shapes whose value domain is enumerable, i.e. the ones that expand per value.
VALUED_SHAPES = frozenset({'bool', 'enum_scalar', 'enum_list', 'enum_nested'})
BOOL_VALUES = ('true', 'false')


def dedup_dirs(dirs):
    """Normalise and order-preserving-dedup dir args.

    Passing a dir twice (or as both --inc and --experimental) would otherwise
    emit every attr twice and silently double the denominator.
    """
    out = []
    for d in dirs or ():
        key = os.path.normpath(d)
        if key not in out:
            out.append(key)
    return out


def header_paths(dirs):
    for d in dirs:
        for fn in sorted(os.listdir(d)):
            if fn.endswith('.h'):
                yield os.path.join(d, fn)


def excluded_ops(attr):
    """Ops of ``attr`` that must not reach the denominator (see parse_sai_headers)."""
    if attr.startswith(EXCLUDED_ATTR_PREFIXES):
        return frozenset(OPS)
    for prefix, ops in EXCLUDED_ATTR_OPS.items():
        if attr.startswith(prefix):
            return ops
    return frozenset()


def value_domain(shape, enum_type, enums):
    if shape == 'bool':
        return BOOL_VALUES
    if enum_type:
        members = enums.get(enum_type) or {}
        return tuple(members[k] for k in sorted(members, key=int))
    return ()


def build_cells(attrs, enums):
    """Expand the attr DB into capability cells. Returns (cells, stats)."""
    cells = []
    stats = collections.Counter()
    for a in attrs:
        attr = a['attr']
        shape, enum_type = classify_shape(a['type'], enums)
        values = value_domain(shape, enum_type, enums)
        if shape in VALUED_SHAPES and not values:
            # An enum whose every member is a range marker: keep the attr in the
            # denominator at attr granularity rather than dropping it silently.
            print('warning: %s (@type %s) has no expandable value, keeping it '
                  'at attr level' % (attr, a['type']), file=sys.stderr)
            stats['empty_value_domain'] += 1
        skip = excluded_ops(attr)
        module = os.path.splitext(a['header'])[0]
        for op in OPS:
            applicable = bool(a['applicable'].get(OP_TO_FLAG_KEY[op]))
            if not applicable:
                continue
            expand = op != 'read' and shape in VALUED_SHAPES and values
            if op in skip:
                stats['excluded_cells'] += len(values) if expand else 1
                continue
            for value in (values if expand else (None,)):
                cells.append({'module': module,
                              'attr': attr,
                              'op': op,
                              'value': value,
                              'enum_type': enum_type,
                              'shape': shape,
                              'applicable': applicable})
            stats['shape:' + shape] += len(values) if expand else 1
    return cells, stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--inc', action='append', required=True,
                    help='standard SAI header dir defining the attr universe '
                         '(repeatable)')
    # Vendor / experimental headers contribute their value enums (an @type in
    # inc/ may name an enum declared there) but not their attrs: the skeleton is
    # the vendor-neutral OCP spec denominator, and a chip cannot be scored
    # against another vendor's private attrs.
    ap.add_argument('--experimental', action='append', default=[],
                    help='extra header dir scanned for value enums only')
    ap.add_argument('--enum-values', required=True,
                    help="gen_enum_values.py output: the single definition of "
                         "what counts as a value")
    ap.add_argument('--out', required=True, help='output skeleton JSON')
    args = ap.parse_args()

    attr_dirs = dedup_dirs(args.inc)
    enum_dirs = dedup_dirs(attr_dirs + dedup_dirs(args.experimental))
    bad = [d for d in attr_dirs if not os.path.isdir(d)]
    for d in bad:
        print("error: '%s' is not a directory (expected a SAI header tree "
              "containing sai*.h)" % d, file=sys.stderr)
    if bad:
        return 2

    with open(args.enum_values) as f:
        enums = json.load(f)
    attrs = []
    for path in header_paths(attr_dirs):
        got, _aliases = parse_header(path)
        attrs.extend(got)

    if not attrs:
        # Never write an empty-but-valid skeleton: downstream would build a
        # 0-cell report and CI would call it a pass.
        print("error: no SAI attrs found in %s -- does --inc point at the SAI "
              "'inc' tree containing sai*.h?"
              % ', '.join("'%s'" % d for d in attr_dirs), file=sys.stderr)
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
    with open(args.out, 'w') as f:
        json.dump(skeleton, f, indent=1)

    shapes = collections.Counter(c['shape'] for c in cells)
    print('%d attrs + %d value enums -> %d cells (denominator) -> %s'
          % (len(attrs), len(enums), len(cells), args.out))
    print('per shape: ' + ', '.join('%s(%d)' % kv for kv in sorted(shapes.items())))
    print('excluded from denominator: %d cell(s) (%s prefixes, %s)'
          % (stats['excluded_cells'], ', '.join(EXCLUDED_ATTR_PREFIXES),
             ', '.join('%s%s' % (p, sorted(o))
                       for p, o in sorted(EXCLUDED_ATTR_OPS.items()))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
