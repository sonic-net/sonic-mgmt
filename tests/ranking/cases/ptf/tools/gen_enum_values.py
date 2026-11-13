#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the (enum type, value) -> member name reverse map from SAI headers.

Keyed by enum type on purpose: the same numeric value is reused across enums
(SAI_PACKET_ACTION_DROP and SAI_VLAN_FLOOD_CONTROL_TYPE_ALL are both 0), so a
value-only key silently mislabels values in the report.
"""
import argparse
import glob
import json
import os
import re
import sys

ENUM_RE = re.compile(r'typedef enum _(\w+)\s*\{(.*?)\}\s*\1\s*;', re.S)
MEMBER_RE = re.compile(r'^\s*(SAI_[A-Z0-9_]+)\s*(?:=\s*([^,\n]+?))?\s*,?\s*$')
COMMENT_RE = re.compile(r'/\*.*?\*/')
SHIFT_RE = re.compile(r'^(\d+)\s*<<\s*(\d+)$')
# Not values: *_RANGE_BASE/_START/_END anchor vendor-private space, and *_MAX /
# *_MIN are bounds. A chip cannot be asked to support them.
SENTINEL_RE = re.compile(r'_(START|END|RANGE_BASE|MAX|MIN)$')


def parse_enums(text):
    """{enum_type: {value_str: member_name}} for one header's contents."""
    out = {}
    for m in ENUM_RE.finditer(text):
        name, body = m.group(1), m.group(2)
        members, nxt = {}, 0
        for line in body.split('\n'):
            mm = MEMBER_RE.match(COMMENT_RE.sub('', line))
            if not mm:
                continue
            member, expr = mm.group(1), mm.group(2)
            if expr is not None:
                expr = expr.strip()
                shift = SHIFT_RE.match(expr)
                if re.fullmatch(r'-?\d+', expr):
                    nxt = int(expr)
                elif re.fullmatch(r'0[xX][0-9a-fA-F]+', expr):
                    nxt = int(expr, 16)
                elif shift:
                    nxt = int(shift.group(1)) << int(shift.group(2))
                else:
                    # Alias of another member (e.g. _START = _INGRESS); skip it
                    # but do not disturb the running counter.
                    continue
            if SENTINEL_RE.search(member):
                nxt += 1
                continue
            members.setdefault(str(nxt), member)
            nxt += 1
        if members:
            out[name] = members
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--inc', required=True, help='SAI inc/ directory')
    ap.add_argument('--experimental', help='optional experimental/ directory')
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    paths = sorted(glob.glob(os.path.join(args.inc, '*.h')))
    if args.experimental:
        paths += sorted(glob.glob(os.path.join(args.experimental, '*.h')))

    merged = {}
    for p in paths:
        with open(p, encoding='utf-8', errors='ignore') as f:
            for k, v in parse_enums(f.read()).items():
                merged.setdefault(k, {}).update(v)

    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=2, sort_keys=True)

    total = sum(len(v) for v in merged.values())
    sys.stderr.write('enum_values: %d enums, %d members\n' % (len(merged), total))
    return 0


if __name__ == '__main__':
    sys.exit(main())
