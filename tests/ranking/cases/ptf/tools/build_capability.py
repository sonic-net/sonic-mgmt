#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Join per-case attr records with case outcomes into a three-state verdict.

Verdict source is the case outcome only (Q4 final): SAI status is not consulted
and records carry no phase. Aggregation is pessimistic -- one failing source
marks the whole cell not_supported.
"""
import argparse
import glob
import json
import os
import sys

SUPPORTED, NOT_SUPPORTED, NOT_TESTED = 'supported', 'not_supported', 'not_tested'


def classify_outcome(raw):
    """ptf_results.json string -> verdict contribution.

    A skip counts as not supported. Both kinds mean the same thing here: the
    adapter raises SkipTest when the chip answers SAI_STATUS_NOT_SUPPORTED
    (sai_adapter.py, generated from meta/templates/sai_adapter.py.tt), and the
    hand-written skips say it outright ("not supported on brcm"). Calling either
    one untested would report the strongest negative evidence as no evidence.

    Safe by construction: a skip during setUp leaves no result JSON, hence no
    records, so only a skip that reached the attributes gets classified here.
    """
    if raw == 'OK':
        return SUPPORTED
    if 'skipped=' in raw:
        return NOT_SUPPORTED
    if raw.startswith('FAILED') or raw in ('TIMEOUT', 'ERROR'):
        return NOT_SUPPORTED
    return NOT_TESTED          # Unknown / unrecognised: do not claim a capability


def aggregate(verdicts):
    if NOT_SUPPORTED in verdicts:
        return NOT_SUPPORTED
    if SUPPORTED in verdicts:
        return SUPPORTED
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
    """Numeric -> member name, scoped by enum type (values collide across enums)."""
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
    counts = {SUPPORTED: 0, NOT_SUPPORTED: 0, NOT_TESTED: 0}
    for c in skel:
        key = (c['attr'], c['op'], c.get('value'))
        sources = hits.get(key, [])
        verdict = aggregate([classify_outcome(s['outcome']) for s in sources])
        counts[verdict] += 1
        cells.append(dict(c, verdict=verdict, sources=sources))

    doc = {'cells': cells,
           'summary': dict(counts, total=len(cells), unjoined_records=unjoined)}
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2)

    sys.stderr.write(
        'capability: total=%d supported=%d not_supported=%d not_tested=%d '
        'unjoined=%d\n' % (len(cells), counts[SUPPORTED], counts[NOT_SUPPORTED],
                           counts[NOT_TESTED], unjoined))
    if unjoined:
        sys.stderr.write(
            'WARNING: %d records had no matching case in ptf_results.json -- '
            'identity mismatch between collection and orchestration\n' % unjoined)
    return 0


if __name__ == '__main__':
    sys.exit(main())
