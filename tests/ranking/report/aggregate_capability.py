"""Join captured attribute records with final case results.

Verdict source is the final case status only. Individual SAI call status is not
consulted, so a passing negative test still contributes positive evidence.
"""

SUPPORTED = 'supported'
PARTIALLY_SUPPORTED = 'partially_supported'
NOT_SUPPORTED = 'not_supported'
NOT_TESTED = 'not_tested'


def classify_status(status):
    """Convert a final Run status into capability evidence."""
    if status == 'passed':
        return SUPPORTED
    if status == 'failed':
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


def resolve_value(raw, enum_type, enums):
    """Normalize bools or resolve a numeric value through its enum type."""
    if isinstance(raw, bool):
        return 'true' if raw else 'false'
    if raw is None or enum_type is None:
        return None
    return enums.get(enum_type, {}).get(str(raw))


def build_document(records, skeleton, enums, statuses):
    """Build the capability document consumed by the HTML renderer."""
    enum_by_attr = {}
    for cell in skeleton:
        if cell.get('enum_type'):
            enum_by_attr[cell['attr']] = cell['enum_type']

    hits = {}
    unjoined = 0
    for record in records:
        case = record.get('case')
        if case not in statuses:
            unjoined += 1
            continue
        value = resolve_value(
            record.get('value'), enum_by_attr.get(record['attr']), enums)
        key = (record['attr'], record['op'], value)
        hits.setdefault(key, []).append(
            {'case': case, 'outcome': statuses[case]})

    cells = []
    counts = {SUPPORTED: 0, PARTIALLY_SUPPORTED: 0,
              NOT_SUPPORTED: 0, NOT_TESTED: 0}
    for cell in skeleton:
        key = (cell['attr'], cell['op'], cell.get('value'))
        sources = hits.get(key, [])
        verdict = aggregate([
            classify_status(source['outcome']) for source in sources])
        counts[verdict] += 1
        cells.append(dict(cell, verdict=verdict, sources=sources))
    if unjoined:
        raise ValueError(
            '{} capability records have no matching case status'.format(
                unjoined))
    return {
        'cells': cells,
        'summary': dict(counts, total=len(cells), unjoined_records=unjoined),
    }
