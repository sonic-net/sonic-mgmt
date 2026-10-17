#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the static adapter-function and keyword to SAI attribute mapping."""
import argparse
import json
import re
import sys
from pathlib import Path


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
    """Return function parameters in declaration order with defaults removed."""
    out = {}
    for match in SIGNATURE_RE.finditer(text):
        params = [parameter.split('=')[0].strip()
                  for parameter in match.group(2).split(',')
                  if parameter.strip()]
        out[match.group(1)] = params
    return out


def classify_op(func_name):
    match = re.match(r'sai_thrift_(?:bulk_)?(\w+?)_', func_name)
    return OP_BY_PREFIX.get(match.group(1)) if match else None


def build_map(lines):
    """Scan adapter source into {function|keyword: mapping metadata}."""
    out = {}
    order = {}
    state = {'func': None, 'guard': None, 'union': None, 'attr': None}

    def emit():
        func, guard, attr = state['func'], state['guard'], state['attr']
        if func and guard and attr:
            operation = classify_op(func)
            if operation:
                index = order.get(func, 0)
                out['%s|%s' % (func, guard)] = {
                    'attr': attr,
                    'union': state['union'],
                    'order': index,
                    'op': operation,
                }
                order[func] = index + 1
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
        attr_match = ATTR_RE.search(line)
        if attr_match and state['attr'] is None:
            state['attr'] = attr_match.group(1)
    emit()
    return out


def generate_attr_map(adapter, out):
    text = Path(adapter).read_text(encoding='utf-8', errors='ignore')
    mapping = build_map(text.split('\n'))
    funcs = sorted({key.split('|')[0] for key in mapping})
    func_set = set(funcs)
    signatures = {func: params
                  for func, params in parse_signatures(text).items()
                  if func in func_set}

    envelope = {'schema_version': 1,
                'entries': mapping,
                'signatures': signatures}
    with Path(out).open('w', encoding='utf-8') as output_file:
        json.dump(envelope, output_file, indent=2, sort_keys=True)

    sys.stderr.write('attr_map: %d entries across %d functions, '
                     '%d signatures\n'
                     % (len(mapping), len(funcs), len(signatures)))
    return envelope


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter', required=True, type=Path,
                        help='path to sai_adapter.py')
    parser.add_argument('--out', required=True, type=Path,
                        help='output JSON path')
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    generate_attr_map(args.adapter, args.out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
