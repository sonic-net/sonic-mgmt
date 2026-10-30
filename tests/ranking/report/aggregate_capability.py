#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Join per-case attr records with case outcomes into a four-state verdict.

Verdict source is the case outcome only: SAI status is not consulted and
records carry no phase. Mixed positive and negative evidence is reported as
partially_supported so neither source is hidden.
"""
import argparse
import glob
import json
import os
import re
import sys

SUPPORTED = 'supported'
PARTIALLY_SUPPORTED = 'partially_supported'
NOT_SUPPORTED = 'not_supported'
NOT_TESTED = 'not_tested'
ASSERTION_FAILURE = re.compile(
    r'FAILED \(failures=[1-9][0-9]*'
    r'(?:, (?:errors|skipped|expected failures|unexpected successes)=[0-9]+)*\)')


def classify_outcome(raw):
    """Treat only an explicit assertion failure as negative evidence."""
    if raw == 'OK':
        return SUPPORTED
    if isinstance(raw, str) and ASSERTION_FAILURE.fullmatch(raw):
        return NOT_SUPPORTED
    return NOT_TESTED


def aggregate(verdicts):
    evidence = set(verdicts)
    if SUPPORTED in evidence and NOT_SUPPORTED in evidence:
        return PARTIALLY_SUPPORTED
    if SUPPORTED in evidence:
        return SUPPORTED
    if NOT_SUPPORTED in evidence:
        return NOT_SUPPORTED
    return NOT_TESTED


def load_records(json_dir):
    rows = []
    for p in sorted(glob.glob(os.path.join(json_dir, '*.json'))):
        with open(p, encoding='utf-8') as f:
            try:
                doc = json.load(f)
            except ValueError:
                sys.stderr.write('skip unparsable %s\n' % p)
                continue
        rows.extend(doc.get('attr_records') or [])
    return rows


def resolve_value(raw, enum_type, enums):
    """Normalize bools or resolve a numeric value through its enum type."""
    if isinstance(raw, bool):
        return 'true' if raw else 'false'
    if raw is None or enum_type is None:
        return None
    return enums.get(enum_type, {}).get(str(raw))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--json-dir', required=True)
    ap.add_argument('--skeleton', required=True)
    ap.add_argument('--enum-values', required=True)
    ap.add_argument('--ptf-results', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--allow-unjoined', action='store_true',
                    help='write a diagnostic report when records have no '
                         'matching ptf_results outcome')
    args = ap.parse_args()

    with open(args.skeleton, encoding='utf-8') as f:
        skel = json.load(f)['cells']
    with open(args.enum_values, encoding='utf-8') as f:
        enums = json.load(f)
    with open(args.ptf_results, encoding='utf-8') as f:
        outcomes = json.load(f)

    # cell key -> enum_type, so records can be resolved into the right value
    enum_by_attr = {}
    for c in skel:
        if c.get('enum_type'):
            enum_by_attr[c['attr']] = c['enum_type']

    hits = {}
    unjoined = 0
    for r in load_records(args.json_dir):
        case = r.get('case')
        if case not in outcomes:
            unjoined += 1
            continue
        value = resolve_value(r.get('value'), enum_by_attr.get(r['attr']), enums)
        key = (r['attr'], r['op'], value)
        hits.setdefault(key, []).append(
            {'case': case, 'outcome': outcomes[case]})

    cells = []
    counts = {SUPPORTED: 0, PARTIALLY_SUPPORTED: 0,
              NOT_SUPPORTED: 0, NOT_TESTED: 0}
    for c in skel:
        key = (c['attr'], c['op'], c.get('value'))
        sources = hits.get(key, [])
        verdict = aggregate([classify_outcome(s['outcome']) for s in sources])
        counts[verdict] += 1
        cells.append(dict(c, verdict=verdict, sources=sources))

    sys.stderr.write(
        'capability: total=%d supported=%d partial=%d not_supported=%d '
        'not_tested=%d unjoined=%d\n' %
        (len(cells), counts[SUPPORTED], counts[PARTIALLY_SUPPORTED],
         counts[NOT_SUPPORTED], counts[NOT_TESTED], unjoined))
    if unjoined:
        sys.stderr.write(
            'ERROR: %d records had no matching case in ptf_results.json -- '
            'identity mismatch between collection and orchestration\n' % unjoined)
        if not args.allow_unjoined:
            sys.stderr.write(
                'Refusing to publish an incomplete capability verdict; rerun '
                'with --allow-unjoined only for diagnostics.\n')
            return 1

    doc = {'cells': cells,
           'summary': dict(counts, total=len(cells), unjoined_records=unjoined)}
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2)
    return 0


if __name__ == '__main__':
    sys.exit(main())
