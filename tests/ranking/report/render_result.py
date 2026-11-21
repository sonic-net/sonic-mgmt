"""Render the manifest-wide case execution result."""

from collections import OrderedDict
import html


STATUS_TEXT = {
    'passed': 'PASS',
    'failed': 'FAIL',
    'skipped': 'SKIP',
    'timeout': 'TIMEOUT',
    'not_tested': 'NOT TESTED',
}
STATUS_ORDER = ('passed', 'failed', 'skipped', 'timeout', 'not_tested')

_CSS = """
:root { --bg:#f4f6f8; --panel:#fff; --surface:#f6f8fa;
  --border:#d8dee4; --text:#1f2328; --muted:#59636e;
  --green:#347d39; --green-bg:#eaf3e8; --red:#a40e26;
  --red-bg:#ffebe9; --yellow:#7d5d00; --yellow-bg:#fff8c5;
  --orange:#9a4d00; --orange-bg:#fff1e5; --gray:#59636e;
  --gray-bg:#eaeef2; --blue:#0969da; }
* { box-sizing:border-box; }
body { margin:0; padding:28px; background:var(--bg); color:var(--text);
  font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
.container { max-width:1280px; margin:auto; padding:0; background:var(--panel); }
h1 { margin:0 0 20px; padding-bottom:16px; border-bottom:2px solid #6f7edb;
  font-size:25px; line-height:1.25; }
h2 { margin:0 0 12px; font-size:18px; }
.scope { display:flex; flex-wrap:wrap; gap:8px 20px; margin:12px 0 20px;
  color:var(--muted); }
.scope strong { margin-left:5px; color:var(--text); }
.summary { display:grid; grid-template-columns:repeat(7,minmax(120px,1fr));
  gap:12px; margin-bottom:18px; }
.card { position:relative; min-width:0; padding:14px 16px;
  overflow:hidden; background:var(--surface); border:1px solid var(--border);
  border-radius:9px; }
.card::before { position:absolute; inset:0 auto 0 0; width:4px;
  background:var(--gray); content:""; }
.card span { display:block; margin-bottom:5px; color:var(--muted);
  font-size:11px; font-weight:700; letter-spacing:.06em; text-transform:uppercase; }
.card strong { font-size:24px; line-height:1; }
.card[data-status="passed"]::before { background:var(--green); }
.card[data-status="passed"] strong { color:var(--green); }
.card[data-status="failed"]::before { background:var(--red); }
.card[data-status="failed"] strong { color:var(--red); }
.card[data-status="skipped"]::before { background:var(--yellow); }
.card[data-status="skipped"] strong { color:var(--yellow); }
.card[data-status="timeout"]::before { background:var(--orange); }
.card[data-status="timeout"] strong { color:var(--orange); }
.card[data-status="not_tested"]::before { background:var(--gray); }
.card[data-status="not_tested"] strong { color:var(--gray); }
.card.metric::before { background:#596fd6; }
.distribution { display:flex; width:100%; height:8px; margin:0 0 28px;
  overflow:hidden; background:var(--gray-bg); border-radius:999px; }
.segment { display:block; min-width:0; }
.segment.passed { background:var(--green); }
.segment.failed { background:var(--red); }
.segment.skipped { background:var(--yellow); }
.segment.timeout { background:var(--orange); }
.segment.not_tested { background:#9aa4ae; }
.module { margin-top:12px; overflow:hidden; border:1px solid var(--border);
  border-radius:9px; background:var(--panel); }
.module summary { display:flex; align-items:center; gap:12px; padding:13px 15px;
  cursor:pointer; background:var(--surface); font-weight:600; }
.module summary:hover { background:#eef1f4; }
.module-name { font-size:15px; }
.module-summary { margin-left:auto; color:var(--muted); font-weight:500; }
.table-scroll { overflow-x:auto; }
table { width:100%; border-collapse:collapse; }
th,td { padding:10px 14px; border-top:1px solid var(--border);
  text-align:left; vertical-align:middle; }
th { color:var(--muted); background:#fbfcfd; font-size:11px;
  letter-spacing:.05em; text-transform:uppercase; }
tbody tr:hover { background:#fafbfc; }
.case-name { overflow-wrap:anywhere; }
.duration { white-space:nowrap; font-variant-numeric:tabular-nums; }
.status { display:inline-block; padding:2px 7px; border-radius:5px;
  font-size:12px; font-weight:700; white-space:nowrap; }
.status.passed { color:var(--green); background:var(--green-bg); }
.status.failed { color:var(--red); background:var(--red-bg); }
.status.skipped { color:var(--yellow); background:var(--yellow-bg); }
.status.timeout { color:var(--orange); background:var(--orange-bg); }
.status.not_tested { color:var(--gray); background:var(--gray-bg); }
.log-link { color:var(--blue); text-decoration:none; }
.log-link:hover { text-decoration:underline; }
.empty { padding:24px; color:var(--muted); text-align:center;
  border:1px dashed var(--border); border-radius:8px; }
@media (max-width:1000px) {
  .summary { grid-template-columns:repeat(3,minmax(120px,1fr)); }
}
@media (max-width:640px) {
  .summary { grid-template-columns:repeat(2,minmax(0,1fr)); }
  .module summary { align-items:flex-start; flex-wrap:wrap; }
  .module-summary { width:100%; margin-left:0; }
}
"""


def styles():
    return _CSS


def _duration(value):
    return '—' if value is None else '{:.3f} s'.format(value)


def _percentage(part, total):
    return 0.0 if total == 0 else 100.0 * part / total


def _counts(rows):
    counts = {status: 0 for status in STATUS_ORDER}
    for row in rows:
        status = row['status']
        if status not in STATUS_TEXT:
            raise ValueError('unknown case status: {}'.format(status))
        counts[status] += 1
    return counts


def _case_row(row):
    status = row['status']
    log_href = row.get('log_href')
    log = ('<a class="log-link" href="{}">log</a>'.format(
        html.escape(log_href, quote=True)) if log_href else '—')
    return (
        '<tr><td class="case-name">{}</td>'
        '<td><span class="status {}">{}</span></td>'
        '<td class="duration">{}</td><td>{}</td></tr>'.format(
            html.escape(row['case']), html.escape(status),
            STATUS_TEXT[status], _duration(row.get('duration_seconds')), log))


def _module_summary(counts):
    return ' · '.join(
        '{} {}'.format(counts[status], status.replace('_', ' '))
        for status in STATUS_ORDER if counts[status])


def _module_section(module, rows):
    counts = _counts(rows)
    executed = len(rows) - counts['not_tested']
    open_attr = ' open' if executed else ''
    table_rows = '\n'.join(_case_row(row) for row in rows)
    return '''<details class="module"{open_attr}>
<summary><span class="module-name">{module}</span>
<span class="module-summary">{summary}</span></summary>
<div class="table-scroll"><table><thead><tr><th>Test Case</th>
<th>Status</th><th>Duration</th><th>Log</th></tr></thead>
<tbody>{rows}</tbody></table></div></details>'''.format(
        open_attr=open_attr, module=html.escape(module),
        summary=html.escape(_module_summary(counts)), rows=table_rows)


def render_section(rows):
    """Return document-free manifest-wide result markup."""
    rows = list(rows)
    counts = _counts(rows)
    total = len(rows)
    tested = total - counts['not_tested']
    pass_rate = _percentage(counts['passed'], tested)
    coverage = _percentage(tested, total)

    modules = OrderedDict()
    for row in rows:
        modules.setdefault(row['case'].split('.', 1)[0], []).append(row)

    cards = [
        '<div class="card" data-status="{}"><span>{}</span>'
        '<strong>{}</strong></div>'.format(
            status, status.replace('_', ' ').title(), counts[status])
        for status in STATUS_ORDER
    ]
    cards.extend((
        '<div class="card metric"><span>Pass rate</span>'
        '<strong>{:.1f}%</strong></div>'.format(pass_rate),
        '<div class="card metric"><span>Execution coverage</span>'
        '<strong>{:.1f}%</strong></div>'.format(coverage),
    ))
    segments = [
        '<span class="segment {}" style="width:{:.1f}%" '
        'title="{}: {}"></span>'.format(
            status, _percentage(counts[status], total),
            status.replace('_', ' ').title(), counts[status])
        for status in STATUS_ORDER if counts[status]
    ]
    sections = '\n'.join(
        _module_section(module, module_rows)
        for module, module_rows in modules.items())
    if not sections:
        sections = '<p class="empty">No cases in manifest.</p>'

    return '''<div class="container">
<div class="scope"><div><span>Total</span><strong>{total}</strong></div>
<div><span>Tested</span><strong>{tested}</strong></div>
<div><span>Not tested</span><strong>{not_tested}</strong></div></div>
<section class="summary" aria-label="Test result summary">{cards}</section>
<div class="distribution" aria-label="Test status distribution">{segments}</div>
<h2>Results by Module</h2>{sections}</div>'''.format(
        total=total, tested=tested, not_tested=counts['not_tested'],
        cards='\n'.join(cards), segments=''.join(segments), sections=sections)
