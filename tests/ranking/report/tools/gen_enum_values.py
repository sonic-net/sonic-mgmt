#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the (enum type, value) to member-name reverse map from SAI headers."""
import argparse
import json
import re
import sys
from pathlib import Path


ENUM_RE = re.compile(r'typedef enum _(\w+)\s*\{(.*?)\}\s*\1\s*;', re.S)
MEMBER_RE = re.compile(r'^\s*(SAI_[A-Z0-9_]+)\s*(?:=\s*([^,\n]+?))?\s*,?\s*$')
COMMENT_RE = re.compile(r'/\*.*?\*/')
SHIFT_RE = re.compile(r'^(\d+)\s*<<\s*(\d+)$')
SENTINEL_RE = re.compile(r'_(START|END|RANGE_BASE|MAX|MIN)$')


def parse_enums(text):
    """Return {enum_type: {value_string: member_name}} for one header."""
    out = {}
    for match in ENUM_RE.finditer(text):
        name, body = match.group(1), match.group(2)
        members, values, next_value = {}, {}, 0
        for line in body.split('\n'):
            member_match = MEMBER_RE.match(COMMENT_RE.sub('', line))
            if not member_match:
                continue
            member, expression = member_match.group(1), member_match.group(2)
            if expression is not None:
                expression = expression.strip()
                shift = SHIFT_RE.match(expression)
                if re.fullmatch(r'-?\d+', expression):
                    next_value = int(expression)
                elif re.fullmatch(r'0[xX][0-9a-fA-F]+', expression):
                    next_value = int(expression, 16)
                elif shift:
                    next_value = (int(shift.group(1)) <<
                                  int(shift.group(2)))
                elif expression in values:
                    next_value = values[expression]
                else:
                    continue
            values[member] = next_value
            if SENTINEL_RE.search(member):
                next_value += 1
                continue
            members.setdefault(str(next_value), member)
            next_value += 1
        if members:
            out[name] = members
    return out


def generate_enum_values(inc, experimental, out):
    paths = sorted(Path(inc).glob('*.h'))
    for directory in experimental:
        paths += sorted(Path(directory).glob('*.h'))

    merged = {}
    for path in paths:
        text = path.read_text(encoding='utf-8', errors='ignore')
        for name, members in parse_enums(text).items():
            merged.setdefault(name, {}).update(members)

    with Path(out).open('w', encoding='utf-8') as output_file:
        json.dump(merged, output_file, indent=2, sort_keys=True)

    total = sum(len(members) for members in merged.values())
    sys.stderr.write('enum_values: %d enums, %d members\n'
                     % (len(merged), total))
    return merged


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inc', required=True, type=Path,
                        help='SAI inc/ directory')
    parser.add_argument('--experimental', action='append', default=[],
                        type=Path,
                        help='optional experimental/ directory (repeatable)')
    parser.add_argument('--out', required=True, type=Path)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    generate_enum_values(args.inc, args.experimental, args.out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
