#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the static (adapter function, kwarg) -> attr mapping from sai_adapter.py.

sai_adapter.py spells every mapping out in plain text, so a line scan is enough
and no runtime import of the generated 66k-line module is needed.
"""
import argparse
import json
import re
import sys

# Prefix is a naming convention, not semantics: flush_fdb_entries carries
# CREATE_ONLY attrs, so it must map to 'create' rather than being dropped.
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
    """{func: [param, ...]} in declaration order, defaults stripped.

    The capture layer zips a call's positional args against this list. It cannot
    be derived from the mapped kwargs alone: most functions take an object id or
    entry second, so a ['client', <first mapped kwarg>] guess would assign that
    object id to an attribute the call never set.
    """
    out = {}
    for m in SIGNATURE_RE.finditer(text):
        params = [p.split('=')[0].strip()
                  for p in m.group(2).split(',') if p.strip()]
        out[m.group(1)] = params
    return out


def classify_op(func_name):
    m = re.match(r'sai_thrift_(?:bulk_)?(\w+?)_', func_name)
    return OP_BY_PREFIX.get(m.group(1)) if m else None


def build_map(lines):
    """Scan adapter source lines into {func|kwarg: {attr, union, order, op}}."""
    out = {}
    order = {}
    state = {'func': None, 'guard': None, 'union': None, 'attr': None}

    def emit():
        func, guard, attr = state['func'], state['guard'], state['attr']
        if func and guard and attr:
            op = classify_op(func)
            if op:
                n = order.get(func, 0)
                out['%s|%s' % (func, guard)] = {
                    'attr': attr,
                    'union': state['union'],
                    # append 顺序。本期不参与判定（status 判定已整体作废），保留
                    # 是因为零成本且是将来做 per-attr 定位的唯一依据。
                    'order': n,
                    'op': op,
                }
                order[func] = n + 1
        state['guard'] = state['union'] = state['attr'] = None

    for line in lines:
        m = FUNC_RE.match(line)
        if m:
            emit()
            state['func'] = m.group(1)
            continue
        if state['func'] is None:
            continue
        m = GUARD_RE.match(line)
        if m:
            emit()
            state['guard'] = m.group(1)
            continue
        if state['guard'] is None:
            continue
        # A get-form guard block holds two branches; keep the first attr but let
        # the else-branch supply the union field.
        mv = VALUE_RE.search(line)
        if mv and state['union'] is None:
            state['union'] = mv.group(1)
        ma = ATTR_RE.search(line)
        if ma and state['attr'] is None:
            state['attr'] = ma.group(1)
    emit()
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--adapter', required=True, help='path to sai_adapter.py')
    ap.add_argument('--out', required=True, help='output JSON path')
    args = ap.parse_args()

    with open(args.adapter, encoding='utf-8', errors='ignore') as f:
        text = f.read()
    mapping = build_map(text.split('\n'))
    funcs = sorted({k.split('|')[0] for k in mapping})
    signatures = {f: p for f, p in parse_signatures(text).items() if f in set(funcs)}

    envelope = {'schema_version': 1,
                'entries': mapping,
                'signatures': signatures}
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(envelope, f, indent=2, sort_keys=True)

    sys.stderr.write('attr_map: %d entries across %d functions, %d signatures\n'
                     % (len(mapping), len(funcs), len(signatures)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
