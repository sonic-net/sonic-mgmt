#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Render capability.json into a self-contained HTML capability report.

Layout: one row per attribute, three fixed operation columns (create / set /
read), and a value-level child row per enum/bool value that can be expanded
from the attribute row. Grouping follows the SAI header module. The page
carries its own CSS and JS -- no external assets -- so a vendor can open the
single file straight out of a Jenkins artifact.

Input contract (produced by aggregate_capability.py):

    {"cells": [{"module","attr","op","value","enum_type","shape",
                "applicable","verdict","sources"}],
     "summary": {"supported","not_supported","not_tested","total",
                 "unjoined_records"}}

verdict is one of supported / not_supported / not_tested. A cell with
value=None is attribute-level; a cell with a value is value-level.
"""
import argparse
import html
import json
import sys
import time
from collections import OrderedDict

# Fixed operation columns. The reader always compares the same three, so an
# operation missing from the input still gets a column (rendered as a slash).
OPS = ['create', 'set', 'read']

VERDICTS = ['supported', 'partially_supported', 'not_supported', 'not_tested']

VERDICT_TEXT = {
    'supported': 'Supported',
    'partially_supported': 'PARTIAL',
    'not_supported': 'Not supported',
    'not_tested': 'Not tested',
}

VERDICT_CLASS = {
    'supported': 'yes',
    'partially_supported': 'partial',
    'not_supported': 'no',
    'not_tested': 'na',
}

# Sources beyond this many are folded into a "… +N" hint. The folded ones are
# NOT emitted: a single value can carry 150+ cases and embedding them all
# would multiply the report size for no reader benefit.
MAX_SOURCES = 5

NA_SLASH = '／'
EM_DASH = '—'

_CSS = """
    :root {
      --bg: #f6f8fa;
      --panel: #ffffff;
      --panel-2: #f0f3f6;
      --border: #d0d7de;
      --text: #1f2328;
      --text-dim: #59636e;
      --accent: #0969da;
      --green: #1a7f37;
      --red: #cf222e;
      --amber: #9a6700;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      margin: 0; padding: 28px; background: var(--bg); color: var(--text);
      line-height: 1.5;
    }
    .container {
      max-width: 1500px; margin: 0 auto; background: var(--panel);
      padding: 32px 36px; border-radius: 12px; border: 1px solid var(--border);
      box-shadow: 0 1px 3px rgba(31,35,40,0.12), 0 8px 24px rgba(31,35,40,0.06);
    }
    h1 {
      color: var(--text); font-size: 24px; margin: 0 0 18px;
      padding-bottom: 14px; border-bottom: 2px solid var(--accent);
      letter-spacing: 0.5px;
    }
    h2 {
      color: var(--text); font-size: 17px; margin: 34px 0 4px;
      padding-bottom: 8px; border-bottom: 1px solid var(--border);
    }
    .meta { color: var(--text-dim); font-size: 13px; margin-bottom: 6px; }
    .meta strong { color: var(--text); font-weight: 600; }
    h3 {
      color: var(--text); font-size: 14.5px; font-weight: 600;
      margin: 22px 0 2px;
    }
    table {
      width: 100%; border-collapse: collapse; margin: 10px 0 8px;
      font-size: 13.5px; background: var(--panel); border-radius: 8px; overflow: hidden;
    }
    th, td { padding: 7px 12px; text-align: left; border-bottom: 1px solid var(--border); }
    th {
      background: var(--panel-2); color: var(--text-dim); font-weight: 600;
      text-transform: uppercase; font-size: 11.5px; letter-spacing: 0.6px;
    }
    td { color: var(--text); }
    td.na-slash { color: var(--border); text-align: center; user-select: none; }
    tbody tr:hover { background: rgba(9,105,218,0.06); }
    td strong { color: var(--accent); font-weight: 600; }
    td .na { color: var(--text-dim); }
    td .yes { color: var(--green); font-weight: 700; }
    td .partial { color: var(--amber); font-weight: 700; }
    td .no { color: var(--red); font-weight: 700; }

    /* --- verdict decision matrix (declared x measured) --- */
    .vm-wrap { margin: 18px 0 6px; overflow-x: auto; }
    table.vm { border-collapse: collapse; font-size: 13.5px; width: auto; }
    table.vm th, table.vm td {
      border: 1px solid var(--border); padding: 11px 16px; text-align: center;
    }
    table.vm thead th {
      background: var(--panel-2); color: var(--text-dim); font-weight: 600;
      text-transform: uppercase; font-size: 11.5px; letter-spacing: 0.6px;
    }
    table.vm th.vm-corner {
      background: var(--panel-2); text-align: left; font-weight: 600;
    }
    table.vm th.vm-corner .ax-col {
      display: block; color: var(--accent); text-transform: none;
      letter-spacing: 0; font-size: 11.5px;
    }
    table.vm th.vm-corner .ax-row {
      display: block; color: var(--text-dim); text-transform: none;
      letter-spacing: 0; font-size: 11.5px; margin-top: 2px;
    }
    table.vm tbody th {
      background: var(--panel-2); color: var(--text); font-weight: 600;
      text-align: left; white-space: nowrap;
    }
    table.vm tbody th .hint {
      display: block; color: var(--text-dim); font-weight: 400; font-size: 11px;
    }
    table.vm td .why {
      display: block; color: var(--text-dim); font-weight: 400; font-size: 11px;
      margin-top: 2px;
    }
    .summary-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 16px; margin: 22px 0 8px;
    }
    .summary-card {
      background: var(--panel-2); padding: 18px 20px; border-radius: 10px;
      border: 1px solid var(--border); border-left: 4px solid var(--accent);
    }
    .summary-card.pass { border-left-color: var(--green); }
    .summary-card.partial { border-left-color: var(--amber); }
    .summary-card.fail { border-left-color: var(--red); }
    .summary-card h3 {
      margin: 0 0 10px; font-size: 12px; color: var(--text-dim);
      text-transform: uppercase; letter-spacing: 0.6px; font-weight: 600;
    }
    .summary-card .value { font-size: 30px; font-weight: 700; color: var(--text); }
    .banner {
      background: rgba(210,153,34,0.12); border: 1px solid var(--amber);
      color: var(--amber); padding: 12px 16px; border-radius: 8px; margin: 16px 0;
      font-size: 13.5px;
    }
    .legend {
      margin: 18px 0 2px; font-size: 12px; display: flex; gap: 18px;
      flex-wrap: wrap; align-items: center; color: var(--text-dim);
    }
    /* --- capability matrix: filters, module sections, value child rows --- */
    .filters {
      display: flex; gap: 12px; flex-wrap: wrap; align-items: center;
      margin: 16px 0 4px; font-size: 13px;
    }
    .filters label { color: var(--text-dim); font-size: 12px; }
    .filters select, .filters input {
      font-family: inherit; font-size: 13px; padding: 5px 8px;
      border: 1px solid var(--border); border-radius: 6px;
      background: var(--panel); color: var(--text);
    }
    .filters input { min-width: 260px; }
    #f-stat { color: var(--text-dim); font-size: 12px; margin-left: auto; }
    details.module { margin: 8px 0 18px; }
    details.module.hidden { display: none; }
    details.module > summary {
      cursor: pointer; color: var(--text); font-size: 14px; font-weight: 600;
      padding: 6px 2px; user-select: none;
    }
    details.module > summary:hover { color: var(--accent); }
    details.module > summary .mod-count {
      color: var(--text-dim); font-size: 12px; font-weight: 400; margin-left: 8px;
    }
    td.c-gran { color: var(--text-dim); font-size: 12px; white-space: nowrap; }
    td.c-src { color: var(--text-dim); font-size: 11.5px; }
    td.c-src .src-more { color: var(--accent); margin-left: 4px; }
    .twisty {
      display: inline-block; width: 12px; color: var(--text-dim);
      cursor: pointer; user-select: none; margin-right: 4px;
    }
    .twisty.leaf { cursor: default; }
    tr.child { display: none; background: rgba(9,105,218,0.03); }
    tr.child.shown { display: table-row; }
    tr.child td.c-attr { padding-left: 38px; font-size: 12.5px; }
    tr.hidden { display: none; }
"""

_JS = """
(function () {
  function byId(id) { return document.getElementById(id); }
  var fMod = byId('f-module'), fVer = byId('f-verdict'),
      fGran = byId('f-granularity'), fSearch = byId('f-search'),
      stat = byId('f-stat');
  var rows = [].slice.call(document.querySelectorAll('tr.attr'));
  var kids = {};
  [].forEach.call(document.querySelectorAll('tr.child'), function (tr) {
    var p = tr.getAttribute('data-parent');
    (kids[p] = kids[p] || []).push(tr);
  });

  function matches(tr, mod, ver, gran, term) {
    if (mod && tr.getAttribute('data-module') !== mod) { return false; }
    if (gran && tr.getAttribute('data-granularity') !== gran) { return false; }
    if (ver && tr.getAttribute('data-verdict').split(' ').indexOf(ver) < 0) {
      return false;
    }
    if (term && tr.getAttribute('data-search').indexOf(term) < 0) {
      return false;
    }
    return true;
  }

  function apply() {
    var mod = fMod.value, ver = fVer.value, gran = fGran.value;
    var term = fSearch.value.trim().toLowerCase();
    var shown = 0;
    rows.forEach(function (tr) {
      var ok = matches(tr, mod, ver, gran, term);
      tr.classList.toggle('hidden', !ok);
      if (ok) { shown++; }
      var open = ok && tr.classList.contains('open');
      (kids[tr.getAttribute('data-row')] || []).forEach(function (c) {
        c.classList.toggle('shown', open);
      });
    });
    [].forEach.call(document.querySelectorAll('details.module'),
      function (d) {
        var live = d.querySelectorAll('tr.attr:not(.hidden)').length;
        d.classList.toggle('hidden', live === 0);
        var c = d.querySelector('.mod-count');
        if (c) { c.textContent = live + ' / ' + c.getAttribute('data-total')
                                 + ' attributes'; }
      });
    stat.textContent = shown + ' / ' + rows.length + ' attributes shown';
  }

  function toggle(tr) {
    if (tr.getAttribute('data-granularity') !== 'value') { return; }
    var open = !tr.classList.contains('open');
    tr.classList.toggle('open', open);
    var t = tr.querySelector('.twisty');
    if (t) { t.textContent = open ? '\\u25bc' : '\\u25b6'; }
    (kids[tr.getAttribute('data-row')] || []).forEach(function (c) {
      c.classList.toggle('shown', open);
    });
  }

  rows.forEach(function (tr) {
    var t = tr.querySelector('.twisty');
    if (t && !t.classList.contains('leaf')) {
      t.addEventListener('click', function () { toggle(tr); });
    }
  });
  [fMod, fVer, fGran].forEach(function (el) {
    el.addEventListener('change', apply);
  });
  fSearch.addEventListener('input', apply);
  apply();
})();
"""


def _esc(text):
    return html.escape('' if text is None else str(text))


def _qesc(value):
    """Escape for use inside a double-quoted HTML attribute."""
    return html.escape('' if value is None else str(value), quote=True)


def _combine_verdicts(verdicts):
    evidence = set(verdicts)
    if 'supported' in evidence and 'not_supported' in evidence:
        return 'partially_supported'
    if 'partially_supported' in evidence:
        return 'partially_supported'
    if 'supported' in evidence:
        return 'supported'
    if 'not_supported' in evidence:
        return 'not_supported'
    return 'not_tested'


def _reduce(cells):
    """Collapse duplicate records of one (attr, op[, value]) into one cell."""
    applicable = True
    sources = []
    seen = set()
    verdicts = []
    for c in cells:
        verdicts.append(c.get('verdict') or 'not_tested')
        if not c.get('applicable', True):
            applicable = False
        for s in c.get('sources') or []:
            key = (s.get('case'), s.get('outcome'))
            if key not in seen:
                seen.add(key)
                sources.append(s)
    return {'verdict': _combine_verdicts(verdicts),
            'applicable': applicable, 'sources': sources}


def group_cells(cells):
    """cells -> OrderedDict[module] -> list of attribute records.

    Each attribute record keeps its attribute-level cells per op and its
    value-level cells per (value, op), both as lists so duplicate records are
    reduced rather than dropped.
    """
    modules = OrderedDict()
    index = {}
    for c in cells:
        module = c.get('module') or '(unknown)'
        attr = c.get('attr') or ''
        rows = modules.setdefault(module, [])
        row = index.get((module, attr))
        if row is None:
            row = {'module': module, 'attr': attr, 'header': c.get('header'),
                   'enum_type': c.get('enum_type'),
                   'attr_ops': {}, 'values': OrderedDict()}
            index[(module, attr)] = row
            rows.append(row)
        # An attr-level cell carries enum_type=None while its value-level
        # cells name the enum, so keep the first non-empty one.
        if row['enum_type'] is None:
            row['enum_type'] = c.get('enum_type')
        op = c.get('op')
        value = c.get('value')
        if value is None:
            row['attr_ops'].setdefault(op, []).append(c)
        else:
            row['values'].setdefault(value, OrderedDict()).setdefault(
                op, []).append(c)
    return modules


def _sources_cell(sources):
    """Source column: '<module>.<class> (<outcome>)', folding past MAX_SOURCES."""
    if not sources:
        return '<td class="c-src">%s</td>' % EM_DASH
    shown = sources[:MAX_SOURCES]
    bits = []
    for s in shown:
        case = _esc(s.get('case'))
        outcome = s.get('outcome')
        bits.append('%s (%s)' % (case, _esc(outcome)) if outcome else case)
    text = ', '.join(bits)
    extra = len(sources) - len(shown)
    if extra > 0:
        text += ('<span class="src-more" title="%d more source case(s)">'
                 '&hellip; +%d</span>' % (extra, extra))
    return '<td class="c-src">%s</td>' % text


def _verdict_cell(cell):
    """One op cell: three-state verdict, or a slash when not applicable."""
    if cell is None:
        return '<td class="na-slash">%s</td>' % NA_SLASH
    if not cell.get('applicable', True):
        return ('<td class="na-slash" title="operation not applicable to this '
                'attribute">%s</td>' % NA_SLASH)
    verdict = cell.get('verdict') or 'not_tested'
    return '<td><span class="%s">%s</span></td>' % (
        VERDICT_CLASS.get(verdict, 'na'),
        VERDICT_TEXT.get(verdict, VERDICT_TEXT['not_tested']))


def _aggregate_cell(supported, partial, total):
    """create/set cell: fully-supported values and mixed-evidence values."""
    cls = 'yes' if supported else 'na'
    suffix = ' +%d partial' % partial if partial else ''
    return ('<td title="%d of %d values fully supported; %d partial">'
            '<span class="%s">%d/%d%s</span></td>'
            % (supported, total, partial, cls, supported, total, suffix))


def _row_verdicts(reduced_ops, reduced_values):
    """Verdicts present anywhere in the attr row -- drives the verdict filter."""
    out = []
    for cell in reduced_ops.values():
        if cell['verdict'] not in out:
            out.append(cell['verdict'])
    for per_op in reduced_values.values():
        for cell in per_op.values():
            if cell['verdict'] not in out:
                out.append(cell['verdict'])
    return out


def _search_blob(attr, reduced_ops, reduced_values):
    """Lowercased attr / value / case names so one filter box covers them all."""
    bits = [attr]
    for cell in reduced_ops.values():
        bits.extend(str(s.get('case') or '') for s in cell['sources'])
    for value, per_op in reduced_values.items():
        bits.append(str(value))
        for cell in per_op.values():
            bits.extend(str(s.get('case') or '') for s in cell['sources'])
    return ' '.join(bits).lower()


def _attr_rows(row, row_id):
    """One attribute row plus, when value-level, its child rows."""
    attr = row['attr']
    reduced_ops = OrderedDict(
        (op, _reduce(cells)) for op, cells in row['attr_ops'].items())
    reduced_values = OrderedDict(
        (value, OrderedDict((op, _reduce(cells))
                            for op, cells in per_op.items()))
        for value, per_op in row['values'].items())

    expandable = bool(reduced_values)
    granularity = 'value' if expandable else 'attr'
    if expandable:
        gran_cell = '<td class="c-gran"%s>value (%d)</td>' % (
            (' title="%s"' % _qesc(row['enum_type'])) if row['enum_type'] else '',
            len(reduced_values))
    else:
        gran_cell = '<td class="c-gran">attr</td>'

    out = ['<tr class="attr" data-row="%d" data-module="%s" '
           'data-granularity="%s" data-verdict="%s" data-search="%s">'
           % (row_id, _qesc(row['module']), granularity,
              _qesc(' '.join(_row_verdicts(reduced_ops, reduced_values))),
              _qesc(_search_blob(attr, reduced_ops, reduced_values)))]
    twisty = ('<span class="twisty">&#9654;</span>' if expandable
              else '<span class="twisty leaf"></span>')
    out.append('<td class="c-attr">%s<strong>%s</strong></td>'
               % (twisty, _esc(attr)))
    out.append(gran_cell)
    for op in OPS:
        probed = [v[op] for v in reduced_values.values() if op in v]
        if probed:
            # Fall through to the attr-level cell when no value was probed for
            # this op, so an inapplicable op still reads as a slash, not 0/N.
            supported = sum(1 for c in probed if c['verdict'] == 'supported')
            partial = sum(1 for c in probed
                          if c['verdict'] == 'partially_supported')
            out.append(_aggregate_cell(supported, partial, len(reduced_values)))
        else:
            out.append(_verdict_cell(reduced_ops.get(op)))
    attr_sources = []
    seen = set()
    for cell in reduced_ops.values():
        for s in cell['sources']:
            key = (s.get('case'), s.get('outcome'))
            if key not in seen:
                seen.add(key)
                attr_sources.append(s)
    out.append(_sources_cell(attr_sources))
    out.append('</tr>')

    for value, per_op in reduced_values.items():
        verdicts = []
        sources = []
        seen = set()
        for cell in per_op.values():
            if cell['verdict'] not in verdicts:
                verdicts.append(cell['verdict'])
            for s in cell['sources']:
                key = (s.get('case'), s.get('outcome'))
                if key not in seen:
                    seen.add(key)
                    sources.append(s)
        out.append('<tr class="child" data-parent="%d" data-module="%s" '
                   'data-verdict="%s" data-search="%s">'
                   % (row_id, _qesc(row['module']),
                      _qesc(' '.join(verdicts)),
                      _qesc(('%s %s' % (attr, value)).lower())))
        # Full enum name, never abbreviated: the vendor greps this report for
        # SAI_PACKET_ACTION_DROP, not for DROP.
        out.append('<td class="c-attr">%s</td>' % _esc(value))
        out.append('<td class="c-gran"></td>')
        for op in OPS:
            # A missing value-level op cell means the value does not act on
            # that operation (read is the common case) -> slash.
            out.append(_verdict_cell(per_op.get(op)))
        out.append(_sources_cell(sources))
        out.append('</tr>')
    return out


def _module_section(module, rows, next_row_id):
    header = None
    for row in rows:
        if row.get('header'):
            header = row['header']
            break
    title = '%s (%s)' % (_esc(module), _esc(header)) if header else _esc(module)
    out = ['<details class="module" data-module="%s" open>' % _qesc(module),
           '<summary>%s<span class="mod-count" data-total="%d">%d / %d '
           'attributes</span></summary>'
           % (title, len(rows), len(rows), len(rows)),
           '<table><thead><tr><th>Attr</th><th>Granularity</th>']
    for op in OPS:
        out.append('<th>%s</th>' % _esc(op))
    out.append('<th>Source</th></tr></thead><tbody>')
    for row in rows:
        out.extend(_attr_rows(row, next_row_id))
        next_row_id += 1
    out.append('</tbody></table></details>')
    return out, next_row_id


def _verdict_matrix():
    """How the two inputs -- spec declaration and measurement -- pick a state.

    Wording and colours come from VERDICT_TEXT / VERDICT_CLASS / NA_SLASH so the
    legend cannot drift from the tables it explains.
    """
    def state(key):
        return ('<span class="%s">%s</span>' %
                (VERDICT_CLASS.get(key, 'na'), VERDICT_TEXT[key]))

    def na():
        return '<span class="na-slash">%s</span>' % NA_SLASH

    measured = [('Passed', 'supported', 'all captured evidence passed'),
                ('Mixed', 'partially_supported',
                 'both passing and negative evidence'),
                ('Failed', 'not_supported',
                 'all captured evidence was negative'),
                ('Not run', 'not_tested', 'no evidence either way')]

    out = ['<div class="vm-wrap">', '<table class="vm">', '<thead><tr>',
           '<th class="vm-corner">'
           '<span class="ax-col">Measured on chip &rarr;</span>'
           '<span class="ax-row">&darr; Declared in SAI spec</span></th>']
    for label, _key, _why in measured:
        out.append('<th>%s</th>' % label)
    out.append('</tr></thead><tbody>')

    out.append('<tr><th>Declared'
               '<span class="hint">the spec allows this operation</span></th>')
    for _label, key, why in measured:
        out.append('<td>%s<span class="why">%s</span></td>' % (state(key), why))
    out.append('</tr>')

    out.append('<tr><th>Not declared'
               '<span class="hint">the spec has no such operation</span></th>')
    for _label, _key, _why in measured:
        out.append('<td>%s<span class="why">not applicable</span></td>' % na())
    out.append('</tr>')

    out.append('</tbody></table></div>')
    out.append('<div class="legend"><span>An attribute\'s <strong>@flags</strong> '
               'in the SAI headers -- CREATE_ONLY, CREATE_AND_SET or READ_ONLY -- '
               'decide what is declared. An operation the spec does not define '
               'can be neither supported nor unsupported, so it is never counted '
               'in the totals.</span></div>')
    return out


def _summary_cards(summary):
    total = summary.get('total', 0)
    cards = [('Total', total, ''),
             ('Supported', summary.get('supported', 0), 'pass'),
             ('Partial', summary.get('partially_supported', 0), 'partial'),
             ('Not supported', summary.get('not_supported', 0), 'fail'),
             ('Not tested', summary.get('not_tested', 0), '')]
    out = ['<div class="summary-grid">']
    for title, value, cls in cards:
        out.append('<div class="summary-card %s"><h3>%s</h3>'
                   '<div class="value">%s</div></div>'
                   % (cls, title, value))
    out.append('</div>')
    return out


def _filters(modules):
    out = ['<div class="filters">',
           '<label for="f-module">Module</label>',
           '<select id="f-module"><option value="">All modules</option>']
    for module in modules:
        out.append('<option value="%s">%s</option>'
                   % (_qesc(module), _esc(module)))
    out.append('</select>')
    out.append('<label for="f-verdict">Verdict</label>'
               '<select id="f-verdict"><option value="">All verdicts</option>')
    for verdict in VERDICTS:
        out.append('<option value="%s">%s</option>'
                   % (verdict, VERDICT_TEXT[verdict]))
    out.append('</select>')
    out.append('<label for="f-granularity">Granularity</label>'
               '<select id="f-granularity">'
               '<option value="">All granularities</option>'
               '<option value="attr">attr</option>'
               '<option value="value">value</option></select>')
    out.append('<label for="f-search">Search</label>'
               '<input id="f-search" type="search" '
               'placeholder="attribute, enum value or case name">')
    out.append('<span id="f-stat"></span></div>')
    return out


def _legend():
    return ('<div class="legend">'
            '<span><span class="yes">Supported</span> all captured evidence '
            'passed</span>'
            '<span><span class="partial">PARTIAL</span> both passing and '
            'negative evidence; inspect Sources</span>'
            '<span><span class="no">Not supported</span> all captured evidence '
            'was negative</span>'
            '<span><span class="na">Not tested</span> no case exercised it'
            '</span>'
            '<span>%s on an attribute row: the operation does not apply to '
            'this attribute</span>'
            '<span>%s in a value row read column: the value does not act on '
            'get</span>'
            '<span>n/N: fully supported values out of all values; partial '
            'values are shown separately</span>'
            '</div>' % (NA_SLASH, NA_SLASH))


def render(doc):
    """capability.json dict -> self-contained HTML string."""
    cells = doc.get('cells') or []
    summary = doc.get('summary') or {}
    modules = group_cells(cells)

    out = ['<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">',
           '<meta name="viewport" content="width=device-width, '
           'initial-scale=1.0">',
           '<title>SAI Capability Report</title><style>', _CSS,
           '</style></head><body><div class="container">',
           '<h1>SAI Capability Report</h1>',
           '<div class="meta"><strong>Generated:</strong> %s</div>'
           % time.strftime('%Y-%m-%d %H:%M:%S')]

    unjoined = summary.get('unjoined_records', 0) or 0
    if unjoined:
        out.append('<div class="banner">%d unjoined record(s): probe records '
                   'that matched no attribute cell and are therefore absent '
                   'from the matrix below. The report understates coverage '
                   'until they are joined.</div>' % unjoined)

    out.append('<h2>Overview</h2>')
    out.extend(_summary_cards(summary))
    out.append('<h2>Capability Matrix</h2>')
    out.append('<h3>How each state is decided</h3>')
    out.extend(_verdict_matrix())
    out.extend(_filters(modules))
    out.append(_legend())

    if modules:
        row_id = 0
        for module in sorted(modules):
            section, row_id = _module_section(module, modules[module], row_id)
            out.extend(section)
    else:
        out.append('<div class="meta">No capability cells to render.</div>')

    out.append('<script>%s</script>' % _JS)
    out.append('</div></body></html>')
    return '\n'.join(out)


def main():
    p = argparse.ArgumentParser(
        description='Render capability.json into a self-contained HTML report')
    p.add_argument('--capability', required=True,
                   help='capability.json produced by aggregate_capability.py')
    p.add_argument('--out', required=True, help='output HTML file')
    args = p.parse_args()

    try:
        with open(args.capability, 'r', encoding='utf-8') as f:
            doc = json.load(f)
    except (OSError, ValueError) as e:
        print('Error: cannot read %s: %s' % (args.capability, e),
              file=sys.stderr)
        return 1
    if not isinstance(doc, dict):
        print('Error: %s is not a JSON object' % args.capability,
              file=sys.stderr)
        return 1

    page = render(doc)
    try:
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write(page)
    except OSError as e:
        print('Error: cannot write %s: %s' % (args.out, e), file=sys.stderr)
        return 1
    summary = doc.get('summary') or {}
    print('Capability report generated: %s (%d bytes, %d cells)'
          % (args.out, len(page.encode('utf-8')), summary.get('total', 0)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
