#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vendor-neutral SAI header attribute extractor."""
import argparse
import json
import os
import re
import sys
from pathlib import Path


ENUM_BLOCK_RE = re.compile(
    r'typedef\s+enum\s+_(\w+_attr(?:_extensions)?_t)\s*\{(.*?)\}\s*\1\s*;',
    re.DOTALL)
# This negative lookahead must stop at the first comment terminator. A lazy
# wildcard backtracks across adjacent comments and changes four SAI enum parses.
MEMBER_RE = re.compile(
    r'(/\*\*(?:(?!\*/).)*?\*/)?\s*\n?\s*(SAI_[A-Z0-9_]+)\s*(?:=\s*[^,}]+)?'
    r'(?:,|\s*\Z)',
    re.DOTALL)
# Doxygen must win before ordinary block comments so metadata is retained while
# commented-out enum members cannot become phantom denominator rows.
COMMENT_SCAN_RE = re.compile(
    r'(?P<doc>/\*\*(?:(?!\*/).)*?\*/)'
    r'|(?P<block>/\*(?:(?!\*/).)*?\*/)'
    r'|(?P<line>//[^\n]*)',
    re.DOTALL)
DOXYGEN_TAG_RE = re.compile(r'@(\w+)\s+([^\n@]*)', re.MULTILINE)
ALIAS_IGNORE_RE = re.compile(r'@ignore\b')
ATTR_ENUM_SUFFIX_RE = re.compile(r'_attr(?:_extensions)?_t$')

SKIP_SUFFIXES = ('_START', '_END', '_ATTR_MAX', '_RANGE_BASE')
# Hostif packet metadata has no CRUD object, and the adapter exposes no FDB
# flush getter; including those cells would make the denominator unreachable.
EXCLUDED_ATTR_PREFIXES = ('SAI_HOSTIF_PACKET_ATTR_',)
EXCLUDED_ATTR_OPS = {'SAI_FDB_FLUSH_ATTR_': frozenset({'read'})}
ACL_DATA_WRAPPERS = ('sai_acl_action_data_t', 'sai_acl_field_data_t')
ENUM_LIST_WRAPPERS = ('sai_s32_list_t',)


def enum_to_attr_prefix(enum_name):
    """Return the member prefix for an attribute enum."""
    core, count = ATTR_ENUM_SUFFIX_RE.subn('_attr', enum_name)
    if not count:
        core = enum_name[:-2] if enum_name.endswith('_t') else enum_name
    return core.upper() + '_'


def parse_flags(flags_str):
    """Map @flags to per-operation applicability."""
    tokens = set(token.strip() for token in (flags_str or '').split('|')
                 if token.strip())
    if 'READ_ONLY' in tokens:
        return {'create': False, 'set': False, 'get': True}
    if 'CREATE_ONLY' in tokens:
        return {'create': True, 'set': False, 'get': True}
    if 'CREATE_AND_SET' in tokens:
        return {'create': True, 'set': True, 'get': True}
    return {'create': False, 'set': False, 'get': True,
            '_unknown_flags': True}


def strip_non_doc_comments(body):
    """Remove commented-out code while retaining Doxygen metadata."""
    out = []
    position = 0
    for match in COMMENT_SCAN_RE.finditer(body):
        if match.lastgroup == 'doc':
            continue
        out.append(body[position:match.start()])
        out.append('\n' * match.group().count('\n'))
        position = match.end()
    if not out:
        return body
    out.append(body[position:])
    return ''.join(out)


def parse_header(path):
    path = Path(path)
    text = path.read_text(encoding='utf-8', errors='replace')
    out = []
    aliases = []
    for match in ENUM_BLOCK_RE.finditer(text):
        enum_name, body = match.group(1), match.group(2)
        prefix = enum_to_attr_prefix(enum_name)
        body = strip_non_doc_comments(body)
        for member_match in MEMBER_RE.finditer(body):
            doc, name = member_match.group(1) or '', member_match.group(2)
            if not name.startswith(prefix.rstrip('_')):
                continue
            if name.endswith(SKIP_SUFFIXES) or '_CUSTOM_RANGE_' in name:
                continue
            if ALIAS_IGNORE_RE.search(doc):
                aliases.append(name)
                continue
            tags = {}
            for tag_match in DOXYGEN_TAG_RE.finditer(doc):
                key = tag_match.group(1)
                value = tag_match.group(2).strip().rstrip('*/ ').strip()
                if key in ('type', 'flags', 'objects', 'default',
                           'isresourcetype', 'condition', 'validonly'):
                    tags.setdefault(key, value)
            brief = ''
            for line in doc.splitlines():
                line = line.strip().lstrip('/*').strip()
                if line and not line.startswith('@'):
                    brief = line
                    break
            param = name[len(prefix):].lower() if name.startswith(prefix) else ''
            out.append({
                'attr': name,
                'enum': enum_name,
                'header': path.name,
                'param': param,
                'brief': brief,
                'type': tags.get('type', ''),
                'flags': tags.get('flags', ''),
                'objects': tags.get('objects', ''),
                'default': tags.get('default', ''),
                'condition': tags.get('condition', ''),
                'validonly': tags.get('validonly', ''),
                'isresourcetype': tags.get('isresourcetype', '') == 'true',
                'applicable': parse_flags(tags.get('flags', '')),
            })
    return out, aliases


def classify_shape(type_str, enums):
    """Map a Doxygen @type to (shape, enum_type)."""
    parts = (type_str or '').split()
    if len(parts) == 1:
        if parts[0] == 'bool':
            return 'bool', None
        if parts[0] in enums:
            return 'enum_scalar', parts[0]
    elif len(parts) == 2:
        wrapper, leaf = parts
        if wrapper in ACL_DATA_WRAPPERS:
            if leaf == 'bool':
                return 'bool', None
            if leaf in enums:
                return 'enum_nested', leaf
        elif wrapper in ENUM_LIST_WRAPPERS and leaf in enums:
            return 'enum_list', leaf
    return 'opaque', None


def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inc-dir', action='append', required=True, type=Path,
                        help='SAI header dir (repeatable, e.g. inc + experimental)')
    parser.add_argument('-o', '--output', default=Path('sai_attr_db.json'),
                        type=Path)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)

    inc_dirs = []
    for directory in args.inc_dir:
        key = os.path.normpath(str(directory))
        if key not in inc_dirs:
            inc_dirs.append(key)

    bad = [directory for directory in inc_dirs
           if not Path(directory).is_dir()]
    for directory in bad:
        print("error: --inc-dir '%s' is not a directory (expected the SAI "
              "'inc' tree containing sai*.h)" % directory, file=sys.stderr)
    if bad:
        return 2

    attrs = []
    skipped_aliases = []
    files = 0
    for directory in inc_dirs:
        for path in sorted(Path(directory).iterdir()):
            if path.suffix != '.h':
                continue
            got, aliases = parse_header(path)
            skipped_aliases.extend(aliases)
            if got:
                files += 1
                attrs.extend(got)

    ext_attrs = [attr for attr in attrs
                 if attr['enum'].endswith('_attr_extensions_t')]
    unknown_flags = [attr['attr'] for attr in attrs
                     if attr['applicable'].get('_unknown_flags')]

    if not attrs:
        print("error: no SAI attrs found in %s -- does --inc-dir point at the "
              "SAI 'inc' tree containing sai*.h? (a repo root or 'include' "
              "dir will parse to nothing)"
              % ', '.join("'%s'" % directory for directory in inc_dirs),
              file=sys.stderr)
        return 1

    db = {'source_dirs': inc_dirs, 'header_files': files,
          'attr_count': len(attrs),
          'extension_attr_count': len(ext_attrs),
          'skipped_alias_count': len(skipped_aliases),
          'skipped_aliases': sorted(skipped_aliases),
          'unknown_flags_count': len(unknown_flags),
          'attrs': attrs}
    with args.output.open('w', encoding='utf-8') as output_file:
        json.dump(db, output_file, indent=1)
    per_header = {}
    for attr in attrs:
        per_header[attr['header']] = per_header.get(attr['header'], 0) + 1
    top = sorted(per_header.items(), key=lambda item: -item[1])[:6]
    print('parsed %d attrs from %d headers -> %s'
          % (len(attrs), files, args.output))
    print('top: ' + ', '.join('%s(%d)' % item for item in top))
    ext_per_enum = {}
    for attr in ext_attrs:
        ext_per_enum[attr['enum']] = ext_per_enum.get(attr['enum'], 0) + 1
    print('vendor extension attrs: %d from %d _attr_extensions_t enum(s)%s'
          % (len(ext_attrs), len(ext_per_enum),
             (': ' + ', '.join('%s(%d)' % item
                               for item in sorted(ext_per_enum.items())))
             if ext_per_enum else ''))
    print('skipped %d @ignore alias attr(s)%s'
          % (len(skipped_aliases),
             (': ' + ', '.join(sorted(skipped_aliases)))
             if skipped_aliases else ''))
    if unknown_flags:
        print('unknown/empty @flags -> get-only fallback: %d (%s)'
              % (len(unknown_flags), ', '.join(sorted(unknown_flags))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
