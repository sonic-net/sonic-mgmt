#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""parse_sai_headers.py - Vendor-neutral SAI header attr extractor.

Scans SAI ``inc/`` (and optionally ``experimental/``) headers, extracts every
``sai_*_attr_t`` **and** ``sai_*_attr_extensions_t`` enum member together with
its Doxygen metadata (@type/@flags/@objects/@default/@isresourcetype), and
emits a JSON skeleton. ``@ignore`` backward-compatibility aliases are skipped
so each attr appears exactly once.

Reusable across vendors: point --inc-dir at any SAI header tree
(BRCM / Centec / Cisco all ship the same OCP header format, and all put their
private attrs in ``sai_*_attr_extensions_t``).

Usage:
    python3 parse_sai_headers.py --inc-dir ../inc [--inc-dir ../experimental] \
        -o sai_attr_db.json
"""
import argparse
import json
import os
import re
import sys

# Attr enums come in two flavours, both must be scanned:
#   sai_<obj>_attr_t             -> OCP standard attributes
#   sai_<obj>_attr_extensions_t  -> vendor private attributes (experimental/)
# Anything else (e.g. sai_tam_event_attr_qual_t, sai_*_stat_t) stays unmatched.
ENUM_BLOCK_RE = re.compile(
    r'typedef\s+enum\s+_(\w+_attr(?:_extensions)?_t)\s*\{(.*?)\}\s*\1\s*;',
    re.DOTALL)
# NOTE: "(?:(?!\*/).)*?" is a negative lookahead that hard-stops the comment
# body at its own first "*/". Do NOT "simplify" it to ".*?" here: this group is
# optional and followed by more pattern, so under re.DOTALL backtracking lets a
# single match swallow two adjacent comments (a "/** READ_WRITE */" one-liner
# followed by a real "/** ... */" block). Verified: ".*?" changes the parse of
# 4 enum bodies - inc/sailag.h, inc/saineighbor.h, inc/sairoute.h,
# inc/saitunnel.h. The idiom is repeated in COMMENT_SCAN_RE for consistency.
MEMBER_RE = re.compile(
    r'(/\*\*(?:(?!\*/).)*?\*/)?\s*\n?\s*(SAI_[A-Z0-9_]+)\s*(?:=\s*[^,}]+)?'
    r'(?:,|\s*\Z)',
    re.DOTALL)
# Comment scanner used to drop commented-out enum members before MEMBER_RE
# runs. Alternative order matters: 'doc' must be tried first so that a Doxygen
# "/** ... */" block is claimed (and preserved) before 'block' can match its
# leading "/*". Vendor extension headers routinely park not-yet-released attrs
# behind "// SAI_X_ATTR_Y = 0x10," or "/* SAI_X_ATTR_Y = 0x10, */"; without
# this pass they become phantom attrs that pollute the checklist denominator.
COMMENT_SCAN_RE = re.compile(
    r'(?P<doc>/\*\*(?:(?!\*/).)*?\*/)'
    r'|(?P<block>/\*(?:(?!\*/).)*?\*/)'
    r'|(?P<line>//[^\n]*)',
    re.DOTALL)
DOXYGEN_TAG_RE = re.compile(r'@(\w+)\s+([^\n@]*)', re.MULTILINE)
# "/** @ignore - for backward compatibility */" marks a same-value alias of a
# real attr (X = Y). Emitting it would duplicate the checklist row and, since
# the alias carries no @flags of its own, would also mis-derive applicable.
ALIAS_IGNORE_RE = re.compile(r'@ignore\b')
ATTR_ENUM_SUFFIX_RE = re.compile(r'_attr(?:_extensions)?_t$')

SKIP_SUFFIXES = ('_START', '_END', '_ATTR_MAX', '_RANGE_BASE')

# Attrs whose cells must stay out of the checklist denominator: rx/tx packet
# metadata handed to hostif packet send/recv, not attributes of any CRUD
# object, so no create/set/get call site exists for them.
EXCLUDED_ATTR_PREFIXES = ('SAI_HOSTIF_PACKET_ATTR_',)
# Per-(attr prefix, op) exclusions. sai_adapter exposes no
# get_fdb_flush_attribute(), so the read cells of SAI_FDB_FLUSH_ATTR_* are
# untestable by construction while their create cells are fine.
EXCLUDED_ATTR_OPS = {'SAI_FDB_FLUSH_ATTR_': frozenset({'read'})}

# @type wrappers that only carry a value: the leaf type after them decides the
# shape (inc/saiacl.h: "@type sai_acl_action_data_t sai_packet_action_t").
ACL_DATA_WRAPPERS = ('sai_acl_action_data_t', 'sai_acl_field_data_t')
ENUM_LIST_WRAPPERS = ('sai_s32_list_t',)


def enum_to_attr_prefix(enum_name):
    """sai_route_entry_attr_t     -> SAI_ROUTE_ENTRY_ATTR_
    sai_port_attr_extensions_t -> SAI_PORT_ATTR_

    Extension enums keep the *base* object's member prefix: members of
    sai_port_attr_extensions_t are named SAI_PORT_ATTR_*, never
    SAI_PORT_ATTR_EXTENSIONS_*. A plain upper() would derive the wrong prefix
    and the member prefix guard below would drop every extension attr.
    """
    core, n = ATTR_ENUM_SUFFIX_RE.subn('_attr', enum_name)
    if not n:
        core = enum_name[:-2] if enum_name.endswith('_t') else enum_name
    return core.upper() + '_'


def parse_flags(flags_str):
    """Map @flags to per-operation applicability."""
    tokens = set(t.strip() for t in (flags_str or '').split('|') if t.strip())
    if 'READ_ONLY' in tokens:
        return {'create': False, 'set': False, 'get': True}
    if 'CREATE_ONLY' in tokens:
        return {'create': True, 'set': False, 'get': True}
    if 'CREATE_AND_SET' in tokens:
        return {'create': True, 'set': True, 'get': True}
    # Unknown / empty flags: be genuinely conservative and only claim get.
    # Claiming create+set here would mark READ_ONLY-ish attrs as "should be
    # tested", i.e. fail the checklist for operations the SAI spec forbids.
    # _unknown_flags lets downstream reports flag these rows for review.
    return {'create': False, 'set': False, 'get': True, '_unknown_flags': True}


def strip_non_doc_comments(body):
    """Remove commented-out code from an enum body, keep Doxygen metadata.

    Drops ``//`` line comments and plain ``/* ... */`` block comments, but
    preserves Doxygen ``/** ... */`` blocks verbatim because @type/@flags live
    in them. Removed spans are replaced by their own newlines so line structure
    (which MEMBER_RE relies on) and reported ordering stay unchanged.
    """
    out = []
    pos = 0
    for m in COMMENT_SCAN_RE.finditer(body):
        if m.lastgroup == 'doc':
            continue                     # keep documentation comments as-is
        out.append(body[pos:m.start()])
        out.append('\n' * m.group().count('\n'))
        pos = m.end()
    if not out:
        return body
    out.append(body[pos:])
    return ''.join(out)


def parse_header(path):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()
    out = []
    aliases = []
    for m in ENUM_BLOCK_RE.finditer(text):
        enum_name, body = m.group(1), m.group(2)
        prefix = enum_to_attr_prefix(enum_name)
        # Must run before MEMBER_RE: its doc-comment group is optional, so a
        # commented-out "SAI_X_ATTR_Y = 2," would otherwise be harvested as a
        # real (flag-less) attr.
        body = strip_non_doc_comments(body)
        for mm in MEMBER_RE.finditer(body):
            doc, name = mm.group(1) or '', mm.group(2)
            if not name.startswith(prefix.rstrip('_')):
                continue
            if name.endswith(SKIP_SUFFIXES) or '_CUSTOM_RANGE_' in name:
                continue
            if ALIAS_IGNORE_RE.search(doc):
                # Same-value alias of a real attr, kept only for source
                # compatibility. The canonical attr is emitted separately.
                aliases.append(name)
                continue
            tags = {}
            for t in DOXYGEN_TAG_RE.finditer(doc):
                key, val = t.group(1), t.group(2).strip().rstrip('*/ ').strip()
                if key in ('type', 'flags', 'objects', 'default',
                           'isresourcetype', 'condition', 'validonly'):
                    tags.setdefault(key, val)
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
                'header': os.path.basename(path),
                'param': param,          # sai_adapter kwarg name (template rule)
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
    """Map a Doxygen ``@type`` to ``(shape, enum_type)``.

    ``bool`` / ``enum_scalar`` / ``enum_list`` / ``enum_nested`` have a finite,
    header-declared value domain and are expanded per value by the skeleton
    generator. ``opaque`` (integers, object ids, addresses, structs, function
    pointers) has none, so it stays at attr granularity -- enumerating its
    values would mean hand-picking test points.

    ``enum_type`` is the enum whose members are the values, or None.
    """
    parts = (type_str or '').split()
    if len(parts) == 1:
        if parts[0] == 'bool':
            return 'bool', None
        if parts[0] in enums:
            return 'enum_scalar', parts[0]
    elif len(parts) == 2:
        wrapper, leaf = parts
        if wrapper in ACL_DATA_WRAPPERS:
            # ACL match/action wrapper: the leaf type carries the value domain.
            if leaf == 'bool':
                return 'bool', None
            if leaf in enums:
                return 'enum_nested', leaf
        elif wrapper in ENUM_LIST_WRAPPERS and leaf in enums:
            return 'enum_list', leaf
    return 'opaque', None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--inc-dir', action='append', required=True,
                    help='SAI header dir (repeatable, e.g. inc + experimental)')
    ap.add_argument('-o', '--output', default='sai_attr_db.json')
    args = ap.parse_args()

    # Order-preserving dedup: passing the same dir twice would emit every attr
    # twice and silently double attr_count.
    inc_dirs = []
    for d in args.inc_dir:
        key = os.path.normpath(d)
        if key not in inc_dirs:
            inc_dirs.append(key)

    bad = [d for d in inc_dirs if not os.path.isdir(d)]
    for d in bad:
        print("error: --inc-dir '%s' is not a directory (expected the SAI "
              "'inc' tree containing sai*.h)" % d, file=sys.stderr)
    if bad:
        return 2

    attrs = []
    skipped_aliases = []
    files = 0
    for d in inc_dirs:
        for fn in sorted(os.listdir(d)):
            if not fn.endswith('.h'):
                continue
            got, aliases = parse_header(os.path.join(d, fn))
            skipped_aliases.extend(aliases)
            if got:
                files += 1
                attrs.extend(got)

    ext_attrs = [a for a in attrs if a['enum'].endswith('_attr_extensions_t')]
    unknown_flags = [a['attr'] for a in attrs
                     if a['applicable'].get('_unknown_flags')]

    if not attrs:
        # Never write an empty-but-valid DB: downstream would happily build a
        # 0-row checklist and CI would report success.
        print("error: no SAI attrs found in %s -- does --inc-dir point at the "
              "SAI 'inc' tree containing sai*.h? (a repo root or 'include' "
              "dir will parse to nothing)"
              % ', '.join("'%s'" % d for d in inc_dirs), file=sys.stderr)
        return 1

    db = {'source_dirs': inc_dirs, 'header_files': files,
          'attr_count': len(attrs),
          'extension_attr_count': len(ext_attrs),
          'skipped_alias_count': len(skipped_aliases),
          'skipped_aliases': sorted(skipped_aliases),
          'unknown_flags_count': len(unknown_flags),
          'attrs': attrs}
    with open(args.output, 'w') as f:
        json.dump(db, f, indent=1)
    per_hdr = {}
    for a in attrs:
        per_hdr[a['header']] = per_hdr.get(a['header'], 0) + 1
    top = sorted(per_hdr.items(), key=lambda kv: -kv[1])[:6]
    print('parsed %d attrs from %d headers -> %s' % (len(attrs), files, args.output))
    print('top: ' + ', '.join('%s(%d)' % kv for kv in top))
    ext_per_enum = {}
    for a in ext_attrs:
        ext_per_enum[a['enum']] = ext_per_enum.get(a['enum'], 0) + 1
    print('vendor extension attrs: %d from %d _attr_extensions_t enum(s)%s'
          % (len(ext_attrs), len(ext_per_enum),
             (': ' + ', '.join('%s(%d)' % kv
                               for kv in sorted(ext_per_enum.items())))
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
