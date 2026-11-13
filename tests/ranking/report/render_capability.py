#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Render a capability document into unified-report markup.

Layout: one row per attribute, three fixed operation columns (create / set /
read), and a value-level child row per enum/bool value that can be expanded
from the attribute row. Grouping follows the SAI header module. The renderer
exposes document-free markup, CSS, and local JavaScript for the unified report.

Input contract (produced in memory by aggregate_capability.py):

    {"cells": [{"module","attr","op","value","enum_type","shape",
                "applicable","verdict","sources"}],
     "summary": {"supported","partially_supported","not_supported",
                 "not_tested","total"}}

A cell with value=None is attribute-level; a cell with a value is value-level.
"""
import html
from collections import OrderedDict

# Fixed operation columns. The reader always compares the same three, so an
# operation missing from the input still gets a column (rendered as a slash).
OPS = ['create', 'set', 'read']
OP_LABELS = {'create': 'CREATE', 'set': 'SET', 'read': 'GET'}

VERDICTS = ['supported', 'partially_supported', 'not_supported', 'not_tested']

VERDICT_TEXT = {
    'supported': 'Supported',
    'partially_supported': 'Partially supported',
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

OUTCOME_PRIORITY = {
    'failed': 0,
    'timeout': 1,
    'error': 2,
    'infrastructure': 2,
    'skipped': 3,
    'passed': 4,
}

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

    /* --- verdict decision matrix (allowed operation x test result) --- */
    .vm-wrap { margin: 18px 0 6px; overflow-x: auto; }
    table.vm { border-collapse: collapse; font-size: 13.5px; width: 100%; }
    table.vm th, table.vm td {
      border: 1px solid var(--border); padding: 11px 16px; text-align: center;
    }
    table.vm thead th {
      background: var(--panel-2); color: var(--text-dim); font-weight: 600;
      text-transform: uppercase; font-size: 11.5px; letter-spacing: 0.6px;
    }
    .vm-axis-labels {
      display: flex; flex-direction: column; gap: 5px; font-weight: 600;
    }
    table.vm th.vm-corner {
      background: var(--panel-2); color: var(--text); min-width: 230px;
      text-align: left; text-transform: none; font-size: 13px;
      letter-spacing: 0;
    }
    table.vm tbody th {
      background: var(--panel-2); color: var(--text); font-weight: 600;
      text-align: left; white-space: nowrap;
    }
    .summary-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 10px; margin: 16px 0 8px;
    }
    .summary-card {
      background: var(--panel-2); padding: 13px 15px; border-radius: 8px;
      border: 1px solid var(--border); border-left: 4px solid var(--accent);
    }
    .summary-card.pass { border-left-color: var(--green); }
    .summary-card.partial { border-left-color: var(--amber); }
    .summary-card.fail { border-left-color: var(--red); }
    .summary-card h3 {
      margin: 0 0 6px; font-size: 11px; color: var(--text-dim);
      text-transform: uppercase; letter-spacing: 0.6px; font-weight: 600;
    }
    .summary-card .value { font-size: 24px; font-weight: 700; color: var(--text); }
    .summary-card.secondary .value { color: var(--text-dim); }
    table.verdict-legend {
      margin: 14px 0 2px; border: 1px solid var(--border);
      font-size: 12.5px; table-layout: fixed;
    }
    table.verdict-legend th, table.verdict-legend td {
      padding: 9px 12px; border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    table.verdict-legend th {
      width: 170px; color: var(--text); text-transform: none;
      letter-spacing: 0; font-size: 12.5px; white-space: nowrap;
    }
    table.verdict-legend td { color: var(--text-dim); }
    table.verdict-legend tr:last-child th,
    table.verdict-legend tr:last-child td {
      border-bottom: 0;
    }
    .verdict-note {
      margin: 8px 2px 0; color: var(--text-dim); font-size: 12px;
    }
    /* --- capability matrix: filters, module sections, value child rows --- */
    .filters {
      display: flex; gap: 12px; flex-wrap: wrap; align-items: center;
      position: sticky; top: 0; z-index: 5;
      margin: 12px 0 8px; padding: 10px 0;
      border-bottom: 1px solid var(--border);
      background: var(--panel); font-size: 13px;
    }
    .filters label { color: var(--text-dim); font-size: 12px; }
    .filter-field {
      display: flex; align-items: center; gap: 6px; min-width: 0;
    }
    .filter-field.search { flex: 1 1 280px; }
    .filter-field select { flex: 1 1 auto; min-width: 0; max-width: 100%; }
    .filters select, .filters input {
      font-family: inherit; font-size: 13px; padding: 5px 8px;
      border: 1px solid var(--border); border-radius: 6px;
      background: var(--panel); color: var(--text);
    }
    .filters input { min-width: 260px; }
    #f-stat { color: var(--text-dim); font-size: 12px; margin-left: auto; }
    details.verdict-help {
      margin: 10px 0 16px; border: 1px solid var(--border);
      border-radius: 8px; background: var(--panel-2);
    }
    details.verdict-help > summary {
      cursor: pointer; padding: 9px 12px; color: var(--text-dim);
      font-size: 13px; font-weight: 600; user-select: none;
    }
    .verdict-help-body { padding: 0 12px 12px; }
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
    details.module > summary .mod-risk {
      color: var(--text-dim); font-size: 12px; font-weight: 400;
      margin-left: 10px;
    }
    details.module > summary .mod-risk.yes { color: var(--green); }
    details.module > summary .mod-risk.partial { color: var(--amber); }
    details.module > summary .mod-risk.no { color: var(--red); }
    .gran-tag {
      display: inline-block; margin-left: 8px; padding: 1px 6px;
      border: 1px solid var(--border); border-radius: 10px;
      color: var(--text-dim); background: var(--panel-2);
      font-size: 10.5px; font-weight: 500; vertical-align: middle;
    }
    .evidence {
      margin: 3px 0 0 16px; color: var(--text-dim);
      font-size: 11.5px; font-weight: 400; line-height: 1.35;
    }
    .evidence strong { color: var(--text-dim); font-weight: 600; }
    .evidence-count { margin-bottom: 2px; }
    .evidence-group { margin-top: 1px; overflow-wrap: anywhere; }
    .evidence-group.outcome-failed strong { color: var(--red); }
    .evidence-group.outcome-timeout strong,
    .evidence-group.outcome-error strong,
    .evidence-group.outcome-infrastructure strong { color: var(--amber); }
    .evidence-group.outcome-passed strong { color: var(--green); }
    details.evidence-more { margin-top: 2px; }
    details.evidence-more > summary {
      cursor: pointer; color: var(--accent); font-weight: 600;
      list-style-position: inside;
    }
    .evidence-full { margin: 2px 0 0 12px; }
    .twisty {
      display: inline-block; width: 12px; color: var(--text-dim);
      user-select: none; margin-right: 4px;
    }
    .twisty.leaf { cursor: default; }
    .attr-toggle {
      display: inline-flex; align-items: center; max-width: 100%; padding: 2px 0;
      border: 0; background: transparent; color: inherit; font: inherit;
      text-align: left; cursor: pointer;
    }
    .attr-toggle:hover strong { color: var(--accent); }
    .attr-toggle:focus-visible {
      border-radius: 4px; outline: 2px solid var(--accent); outline-offset: 2px;
    }
    tr.child { display: none; background: rgba(9,105,218,0.03); }
    tr.child.shown { display: table-row; }
    tr.child td.c-attr { padding-left: 38px; font-size: 12.5px; }
    tr.hidden { display: none; }
    @media (max-width: 720px) {
      .filters { position: static; gap: 8px; align-items: stretch; }
      .filter-field { flex: 1 1 160px; }
      .filter-field label { white-space: nowrap; }
      .filter-field.search { flex-basis: 100%; }
      .filter-field.search input { width: 100%; min-width: 0; }
      #f-stat { flex-basis: 100%; margin-left: 0; }
    }
"""

_JS = """
(function () {
  var root = document.getElementById('report-capability-panel') || document;
  function byId(id) { return root.querySelector('#' + id); }
  var fMod = byId('f-module'), fVer = byId('f-verdict'),
      fGran = byId('f-granularity'), fSearch = byId('f-search'),
      stat = byId('f-stat');
  var rows = [].slice.call(root.querySelectorAll('tr.attr'));
  var kids = {};
  [].forEach.call(root.querySelectorAll('tr.child'), function (tr) {
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
    var filtering = !!(mod || ver || gran || term);
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
    [].forEach.call(root.querySelectorAll('details.module'),
      function (d) {
        var live = d.querySelectorAll('tr.attr:not(.hidden)').length;
        d.classList.toggle('hidden', live === 0);
        if (filtering) {
          if (!d.hasAttribute('data-filter-open')) {
            d.setAttribute('data-filter-open', d.open ? 'true' : 'false');
          }
          d.open = live > 0;
        } else if (d.hasAttribute('data-filter-open')) {
          d.open = d.getAttribute('data-filter-open') === 'true';
          d.removeAttribute('data-filter-open');
        }
        var c = d.querySelector('.mod-count');
        if (c) {
          var total = c.getAttribute('data-total');
          c.textContent = filtering
            ? live + ' / ' + total + ' attributes shown'
            : total + ' attributes';
        }
      });
    stat.textContent = shown + ' / ' + rows.length + ' attributes shown';
  }

  function toggle(tr, control) {
    if (tr.getAttribute('data-granularity') !== 'value') { return; }
    var open = !tr.classList.contains('open');
    tr.classList.toggle('open', open);
    var t = tr.querySelector('.twisty');
    if (t) { t.textContent = open ? '\\u25bc' : '\\u25b6'; }
    control.setAttribute('aria-expanded', open ? 'true' : 'false');
    (kids[tr.getAttribute('data-row')] || []).forEach(function (c) {
      c.classList.toggle('shown', open);
    });
  }

  rows.forEach(function (tr) {
    var control = tr.querySelector('.attr-toggle');
    if (control) {
      control.addEventListener('click', function () { toggle(tr, control); });
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


def _evidence(sources):
    """Outcome-grouped source evidence below the attribute or enum value."""
    if not sources:
        return ''

    records = []
    seen = set()
    for source in sources:
        case = str(source.get('case') or '')
        outcome = str(source.get('outcome') or 'unknown').lower()
        key = (case, outcome)
        if key not in seen:
            seen.add(key)
            records.append({'case': case, 'outcome': outcome})

    def sort_key(source):
        outcome = source['outcome']
        return (OUTCOME_PRIORITY.get(outcome, 5), outcome, source['case'])

    records.sort(key=sort_key)
    groups = OrderedDict()
    for source in records:
        groups.setdefault(source['outcome'], []).append(source)

    selected = OrderedDict((outcome, []) for outcome in groups)
    remaining_slots = MAX_SOURCES
    # First reserve one preview slot per outcome so mixed evidence can never
    # render as though every visible case had the same result.
    for outcome, group in groups.items():
        if remaining_slots and group:
            selected[outcome].append(group[0])
            remaining_slots -= 1
    # Fill the remaining preview slots in risk order: failed first, passed last.
    for outcome, group in groups.items():
        if not remaining_slots:
            break
        available = group[len(selected[outcome]):]
        taken = available[:remaining_slots]
        selected[outcome].extend(taken)
        remaining_slots -= len(taken)

    def label(outcome):
        return outcome.replace('_', ' ').capitalize()

    def render_group(outcome, group):
        cases = ', '.join(_esc(source['case']) for source in group)
        return ('<div class="evidence-group outcome-%s"><strong>%s:</strong> '
                '%s</div>' % (_qesc(outcome), _esc(label(outcome)), cases))

    count_bits = ['%d %s' % (len(records),
                             'case' if len(records) == 1 else 'cases')]
    count_bits.extend('%d %s' % (len(group), _esc(outcome))
                      for outcome, group in groups.items())
    out = ['<div class="evidence">',
           '<div class="evidence-count"><strong>Evidence:</strong> %s</div>'
           % ' &middot; '.join(count_bits),
           '<div class="evidence-preview">']
    for outcome, group in selected.items():
        if group:
            out.append(render_group(outcome, group))
    out.append('</div>')

    remaining = OrderedDict()
    for outcome, group in groups.items():
        tail = group[len(selected[outcome]):]
        if tail:
            remaining[outcome] = tail
    remaining_count = sum(len(group) for group in remaining.values())
    if remaining_count:
        out.append('<details class="evidence-more"><summary>Show remaining '
                   '%d</summary><div class="evidence-full">'
                   % remaining_count)
        for outcome, group in remaining.items():
            out.append(render_group(outcome, group))
        out.append('</div></details>')
    out.append('</div>')
    return ''.join(out)


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
    suffix = ' +%d partially supported' % partial if partial else ''
    return ('<td title="%d of %d values fully supported; %d partially '
            'supported">'
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
        gran_tag = '<span class="gran-tag"%s>Enum value (%d)</span>' % (
            (' title="%s"' % _qesc(row['enum_type']))
            if row['enum_type'] else '', len(reduced_values))
    else:
        gran_tag = '<span class="gran-tag">Attribute</span>'

    attr_sources = []
    seen = set()
    for cell in reduced_ops.values():
        for source in cell['sources']:
            key = (source.get('case'), source.get('outcome'))
            if key not in seen:
                seen.add(key)
                attr_sources.append(source)

    child_ids = ['cap-value-%d-%d' % (row_id, index)
                 for index in range(len(reduced_values))]
    out = ['<tr class="attr" data-row="%d" data-module="%s" '
           'data-granularity="%s" data-verdict="%s" data-search="%s">'
           % (row_id, _qesc(row['module']), granularity,
              _qesc(' '.join(_row_verdicts(reduced_ops, reduced_values))),
              _qesc(_search_blob(attr, reduced_ops, reduced_values)))]
    if expandable:
        control = ('<button type="button" class="attr-toggle" '
                   'aria-expanded="false" aria-controls="%s">'
                   '<span class="twisty" aria-hidden="true">&#9654;</span>'
                   '<strong>%s</strong>%s</button>'
                   % (' '.join(child_ids), _esc(attr), gran_tag))
    else:
        control = ('<span class="twisty leaf" aria-hidden="true"></span>'
                   '<strong>%s</strong>%s' % (_esc(attr), gran_tag))
    out.append('<td class="c-attr">%s%s</td>'
               % (control, _evidence(attr_sources)))
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
    out.append('</tr>')

    for value_index, (value, per_op) in enumerate(reduced_values.items()):
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
        out.append('<tr class="child" id="%s" data-parent="%d" data-module="%s" '
                   'data-verdict="%s" data-search="%s">'
                   % (child_ids[value_index], row_id, _qesc(row['module']),
                      _qesc(' '.join(verdicts)),
                      _qesc(('%s %s' % (attr, value)).lower())))
        # Full enum name, never abbreviated: the vendor greps this report for
        # SAI_PACKET_ACTION_DROP, not for DROP.
        out.append('<td class="c-attr">%s%s</td>'
                   % (_esc(value), _evidence(sources)))
        for op in OPS:
            # Applicability belongs to the parent attribute row. A missing
            # value-level cell only means this enum/bool value was not tested
            # for the operation; it must not reuse the parent's slash meaning.
            cell = per_op.get(op)
            if cell is None:
                cell = {'verdict': 'not_tested', 'applicable': True}
            out.append(_verdict_cell(cell))
        out.append('</tr>')
    return out


def _module_stats(rows):
    """Return non-exclusive attribute-level evidence counts for a module."""
    stats = {'total': len(rows), 'tested': 0, 'supported': 0,
             'partial': 0, 'not_supported': 0}
    for row in rows:
        reduced_ops = OrderedDict(
            (op, _reduce(cells)) for op, cells in row['attr_ops'].items())
        reduced_values = OrderedDict(
            (value, OrderedDict((op, _reduce(cells))
                                for op, cells in per_op.items()))
            for value, per_op in row['values'].items())
        verdicts = set(_row_verdicts(reduced_ops, reduced_values))
        if verdicts - {'not_tested'}:
            stats['tested'] += 1
        if 'supported' in verdicts:
            stats['supported'] += 1
        if 'partially_supported' in verdicts:
            stats['partial'] += 1
        if 'not_supported' in verdicts:
            stats['not_supported'] += 1
    return stats


def _module_section(module, rows, next_row_id):
    header = None
    for row in rows:
        if row.get('header'):
            header = row['header']
            break
    title = '%s (%s)' % (_esc(module), _esc(header)) if header else _esc(module)
    stats = _module_stats(rows)
    badges = [
        '<span class="mod-count" data-total="{total}">{total} attributes'
        '</span>'.format(**stats),
        '<span class="mod-risk">{tested} tested</span>'.format(**stats),
    ]
    if stats['supported']:
        badges.append('<span class="mod-risk yes">%d supported</span>'
                      % stats['supported'])
    if stats['partial']:
        badges.append('<span class="mod-risk partial">%d partially supported</span>'
                      % stats['partial'])
    if stats['not_supported']:
        badges.append('<span class="mod-risk no">%d not supported</span>'
                      % stats['not_supported'])
    out = ['<details class="module" data-module="%s">' % _qesc(module),
           '<summary>%s%s</summary>' % (title, ''.join(badges)),
           '<table><thead><tr><th>Attribute</th>']
    for op in OPS:
        out.append('<th>%s</th>' % _esc(OP_LABELS[op]))
    out.append('</tr></thead><tbody>')
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

    measured = [('ALL PASSED', 'supported'),
                ('MIXED', 'partially_supported'),
                ('ALL FAILED', 'not_supported'),
                ('NOT RUN', 'not_tested')]

    out = ['<div class="vm-wrap">', '<table class="vm">', '<thead><tr>',
           '<th class="vm-corner"><div class="vm-axis-labels">'
           '<span>Test results on chip &rarr;</span>'
           '<span>&darr; Operation allowed by SAI</span>'
           '</div></th>']
    for label, _key in measured:
        out.append('<th>%s</th>' % label)
    out.append('</tr></thead><tbody>')

    out.append('<tr><th>ALLOWED</th>')
    for _label, key in measured:
        out.append('<td>%s</td>' % state(key))
    out.append('</tr>')

    out.append('<tr><th>NOT ALLOWED</th>')
    for _label, _key in measured:
        out.append('<td>%s</td>' % na())
    out.append('</tr>')

    out.append('</tbody></table></div>')
    return out


def _summary_cards(summary, attribute_count):
    total = summary.get('total', 0) or 0
    supported = summary.get('supported', 0) or 0
    partial = summary.get('partially_supported', 0) or 0
    not_supported = summary.get('not_supported', 0) or 0
    not_tested = summary.get('not_tested', 0) or 0
    tested = supported + partial + not_supported
    coverage = (100.0 * tested / total) if total else 0.0
    cards = [('Attributes', attribute_count, ''),
             ('Capability cells', total, ''),
             ('Tested cells', tested, ''),
             ('Coverage', '{:.1f}%'.format(coverage), ''),
             ('Supported', supported, 'pass'),
             ('Partially supported', partial, 'partial'),
             ('Not supported', not_supported, 'fail'),
             ('Not tested', not_tested, 'secondary')]
    out = ['<div class="summary-grid">']
    for title, value, cls in cards:
        out.append('<div class="summary-card %s"><h3>%s</h3>'
                   '<div class="value">%s</div></div>'
                   % (cls, title, value))
    out.append('</div>')
    return out


def _filters(modules):
    out = ['<div class="filters">', '<div class="filter-field">',
           '<label for="f-module">Module</label>',
           '<select id="f-module"><option value="">All modules</option>']
    for module in modules:
        out.append('<option value="%s">%s</option>'
                   % (_qesc(module), _esc(module)))
    out.append('</select></div>')
    out.append('<div class="filter-field">'
               '<label for="f-verdict">Verdict</label>'
               '<select id="f-verdict"><option value="">All verdicts</option>')
    for verdict in VERDICTS:
        out.append('<option value="%s">%s</option>'
                   % (verdict, VERDICT_TEXT[verdict]))
    out.append('</select></div>')
    out.append('<div class="filter-field">'
               '<label for="f-granularity">Granularity</label>'
               '<select id="f-granularity">'
               '<option value="">All granularities</option>'
               '<option value="attr">Attribute</option>'
               '<option value="value">Enum value</option></select></div>')
    out.append('<div class="filter-field search">'
               '<label for="f-search">Search</label>'
               '<input id="f-search" type="search" '
               'placeholder="attribute, enum value or case name"></div>')
    out.append('<span id="f-stat"></span></div>')
    return out


def _legend():
    rows = [
        ('Allowed', 'The attribute\'s SAI <strong>@flags</strong> allow this '
         'operation.'),
        ('Not allowed', 'SAI does not allow this operation for the attribute; '
         'it is excluded from capability totals.'),
        ('Supported', 'All conclusive test results passed.'),
        ('Partially supported', 'Both passing and failing conclusive test '
         'results were recorded.'),
        ('Not supported', 'All conclusive test results failed.'),
        ('Not tested', 'No conclusive test results are available.'),
        (NA_SLASH, 'The operation is not allowed by SAI for this attribute.'),
    ]
    out = ['<table class="verdict-legend"><tbody>']
    for term, explanation in rows:
        out.append('<tr><th>%s</th><td>%s</td></tr>' % (term, explanation))
    out.append('</tbody></table>')
    out.append('<p class="verdict-note">Timeout, error, and skipped cases are '
               'inconclusive; they are shown in Evidence and do not change '
               'the verdict.</p>')
    return ''.join(out)


def styles():
    return _CSS


def script():
    return _JS


def render_section(doc):
    """Convert a capability document to document-free section markup."""
    cells = doc.get('cells') or []
    summary = doc.get('summary') or {}
    modules = group_cells(cells)

    out = ['<div class="container">']
    out.append('<h2>Overview</h2>')
    attribute_count = sum(len(rows) for rows in modules.values())
    out.extend(_summary_cards(summary, attribute_count))
    out.append('<h2>Capability Matrix</h2>')
    out.extend(_filters(modules))
    out.append('<details class="verdict-help">'
               '<summary>How verdicts work</summary>'
               '<div class="verdict-help-body">')
    out.extend(_verdict_matrix())
    out.append(_legend())
    out.append('</div></details>')

    if modules:
        row_id = 0
        for module in sorted(modules):
            section, row_id = _module_section(module, modules[module], row_id)
            out.extend(section)
    else:
        out.append('<div class="meta">No capability cells to render.</div>')

    out.append('</div>')
    return '\n'.join(out)
