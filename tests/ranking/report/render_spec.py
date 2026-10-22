#!/usr/bin/env python3
"""
SAI Test Report Generator (metric-centric)

Generates an HTML report organized by METRIC, not by test case. Metrics are
split into three tables by result_type:
  - performance : throughput and latency (entries/s, ms).
  - scale       : capacity (max entries, fill_rate). Absolute value shown.
  - capability  : functional support (1/0). Shown as ✓/✗.

The report is driven by the measured spec results: every spec the run actually
recorded becomes a row.

Test-case pass/fail belongs to the Test Results section, not here. This module
accepts validated in-memory result documents and renders spec values only.
"""

from dataclasses import dataclass
from html import escape
from typing import Dict, List, Optional, Any


_KNOWN_TYPES = ("performance", "scale", "fill_rate", "capability", "incidental")


def _html(value) -> str:
    return escape(str(value), quote=True)


def _norm_type(result_type: Optional[str]) -> str:
    """Validate a registry result type."""
    if result_type not in _KNOWN_TYPES:
        raise ValueError("unknown registry result_type: %r" % result_type)
    return result_type


def _norm_op(operation) -> str:
    return operation if operation else ""


def _report_spec(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Adapt the collector schema for rendering without changing its archive."""
    if "actual_value" not in spec:
        return dict(spec)
    details = dict(spec.get("extra") or {})
    details["count"] = spec.get("count")
    if "duration_seconds" in spec:
        details["duration_seconds"] = spec["duration_seconds"]
    enriched = dict(spec)
    enriched["value"] = spec.get("actual_value")
    enriched["threshold"] = spec.get("baseline")
    enriched["details"] = details
    return enriched


@dataclass
class SpecRow:
    """One measured metric row in the report."""
    spec_name: str
    operation: str
    result_type: str          # performance | scale | capability
    unit: str
    direction: str            # higher_better | lower_better | equal
    value: Optional[float]
    details: Dict[str, Any]
    result: str               # MEASURED | NOT MEASURED
    test_class: str           # source case (provenance only; may be "")
    scenario: str = ""       # case-defined measurement scenario
    occurrence: int = 0      # repeated measurement within the same scenario


@dataclass
class ReportSummary:
    perf_pass: int = 0
    perf_fail: int = 0
    perf_measured: int = 0   # collected, not judged
    perf_total: int = 0
    scale_pass: int = 0
    scale_fail: int = 0
    scale_measured: int = 0
    scale_total: int = 0
    fill_pass: int = 0
    fill_fail: int = 0
    fill_measured: int = 0
    fill_total: int = 0


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def build_actual_specs(results) -> Dict[tuple, Dict[str, Any]]:
    """Build measured specs directly from merged per-case result documents."""
    actual = {}
    occurrences = {}
    for data in results:
        test_class = data.get("case", data.get("test_class", ""))
        for spec in data.get("spec_results", []):
            enriched = _report_spec(spec)
            enriched["test_class"] = test_class
            scenario = str(enriched.get("details", {}).get("scenario") or "")
            identity = (
                spec.get("spec_name", "unknown"),
                _norm_op(spec.get("operation")),
                test_class,
                scenario,
            )
            occurrence = occurrences.get(identity, 0)
            occurrences[identity] = occurrence + 1
            enriched["scenario"] = scenario
            enriched["occurrence"] = occurrence
            key = identity + (occurrence,)
            actual[key] = enriched
    return actual


def build_registry_definitions(registry) -> Dict[tuple, Dict[str, Any]]:
    """Expand a registry document into operation-specific definitions."""
    definitions = {}
    metric_types = {"performance", "scale", "fill_rate", "incidental"}
    for spec_name, definition in registry.items():
        if spec_name.startswith("_") or not isinstance(definition, dict):
            continue
        if _norm_type(definition.get("result_type")) not in metric_types:
            continue
        operations = definition.get("operations") or [None]
        for operation in operations:
            definitions[(spec_name, _norm_op(operation))] = definition
    return definitions


def build_fill_rate_rows(results) -> List[Dict[str, Any]]:
    """Build every fill-rate row directly from per-case result documents.

    Covers all *_fill_rate specs (route fill rates AND fdb_fill_rate). Unlike
    build_actual_specs, this does NOT dedupe by (spec_name, operation).
    """
    out: List[Dict[str, Any]] = []
    for data in results:
        tc = data.get("case", data.get("test_class", ""))
        for spec in data.get("spec_results", []):
            spec = _report_spec(spec)
            name = spec.get("spec_name", "")
            if not name.endswith("_fill_rate"):
                continue
            details = spec.get("details") or {}
            out.append({
                "test_class": tc,
                "spec_name": name,
                "fill": spec.get("value"),
                "attempted": details.get("attempted_count"),
                "installed": details.get("completed_count"),
                "order": details.get("scenario"),
                "result": _decide_result(spec.get("value"),
                                         spec.get("threshold"),
                                         "higher_better"),
            })
    return out


# ---------------------------------------------------------------------------
# Row building (actual-driven)
# ---------------------------------------------------------------------------

def _decide_result(actual, threshold, direction) -> str:
    """Replicate the data-side PASS/FAIL decision for display consistency.

    No threshold is supplied any more (current phase: we only collect the
    chip's measured capability, we do not judge it), so this reports MEASURED
    -- the value was captured but no pass/fail verdict is rendered.
    """
    if not isinstance(actual, (int, float)):
        return "MEASURED"
    if not isinstance(threshold, (int, float)):
        return "MEASURED"  # no threshold -> collect only
    if direction == "equal":
        return "PASS" if actual == threshold else "FAIL"
    if direction == "lower_better":
        return "PASS" if actual <= threshold else "FAIL"
    return "PASS" if actual >= threshold else "FAIL"


def build_spec_rows(actual: Dict[tuple, Dict[str, Any]],
                    expected: Optional[Dict[tuple, Dict[str, Any]]] = None,
                    definitions: Optional[Dict[tuple, Dict[str, Any]]] = None
                    ) -> List[SpecRow]:
    """Build metric rows from the registered skeleton joined with actual data.

    'incidental' specs (e.g. nexthop/vrf tests' borrowed route throughput) are
    intentionally not reported. Without a registry this falls back to the
    previous actual-only behavior.
    """
    rows = []
    expected = expected or {}
    definitions = definitions or expected
    measured_provenance = {}
    for key in sorted(actual):
        spec_name, operation, test_class, scenario, occurrence = key
        base = (spec_name, operation)
        registered = definitions.get(base, {})
        if not registered:
            raise ValueError("unregistered measured spec: %s/%s" % base)
        rt = _norm_type(registered.get("result_type"))
        if rt == "incidental":
            continue
        measured_provenance.setdefault(spec_name, set()).add(
            (test_class, scenario, occurrence))
        measured = actual[key]
        direction = registered.get("direction", "higher_better")
        value = measured.get("value")
        threshold = measured.get("threshold")
        rows.append(SpecRow(
            spec_name=spec_name, operation=operation, result_type=rt,
            unit=registered.get("unit", ""), direction=direction,
            value=value, details=measured.get("details", {}),
            result=_decide_result(value, threshold, direction),
            test_class=test_class, scenario=scenario,
            occurrence=occurrence))

    for spec_name, operation in sorted(expected):
        registered = definitions.get((spec_name, operation), {})
        rt = _norm_type(registered.get("result_type"))
        if rt == "incidental":
            continue
        provenances = measured_provenance.get(spec_name) or {("", "", 0)}
        for test_class, scenario, occurrence in sorted(provenances):
            if (spec_name, operation, test_class, scenario, occurrence) in actual:
                continue
            rows.append(SpecRow(
                spec_name=spec_name, operation=operation, result_type=rt,
                unit=registered.get("unit", ""),
                direction=registered.get("direction", "higher_better"),
                value=None, details={}, result="NOT MEASURED",
                test_class=test_class, scenario=scenario,
                occurrence=occurrence))

    return rows


def summarize(rows: List[SpecRow]) -> ReportSummary:
    s = ReportSummary()
    for r in rows:
        if r.result_type == "performance":
            s.perf_total += 1
            if r.result == "PASS":
                s.perf_pass += 1
            elif r.result == "FAIL":
                s.perf_fail += 1
            elif r.result == "MEASURED":
                s.perf_measured += 1
        elif r.result_type == "scale":
            s.scale_total += 1
            if r.result == "PASS":
                s.scale_pass += 1
            elif r.result == "FAIL":
                s.scale_fail += 1
            elif r.result == "MEASURED":
                s.scale_measured += 1
        elif r.result_type == "fill_rate":
            s.fill_total += 1
            if r.result == "PASS":
                s.fill_pass += 1
            elif r.result == "FAIL":
                s.fill_fail += 1
            elif r.result == "MEASURED":
                s.fill_measured += 1
        # 'incidental' specs are not summarized (and not rendered).
    return s


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _fmt_num(v):
    if isinstance(v, (int, float)):
        return f"{v:,.2f}" if isinstance(v, float) else f"{v:,}"
    return "—"


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

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
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue",
                   Arial, "PingFang SC", "Microsoft YaHei", sans-serif;
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
    h1 .sub { color: var(--text-dim); font-size: 13px; font-weight: 400; margin-left: 12px; }
    .meta { color: var(--text-dim); font-size: 13px; margin-bottom: 6px; }
    .meta strong { color: var(--text); font-weight: 600; }
    h2 {
      color: var(--text); font-size: 17px; margin: 34px 0 4px;
      padding-bottom: 8px; border-bottom: 1px solid var(--border);
    }
    table {
      width: 100%; border-collapse: collapse; margin: 14px 0 8px;
      font-size: 13.5px; background: var(--panel); border-radius: 8px; overflow: hidden;
    }
    .table-scroll {
      max-width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch;
    }
    th, td { padding: 9px 14px; text-align: left; border-bottom: 1px solid var(--border); }
    th {
      background: var(--panel-2); color: var(--text-dim); font-weight: 600;
      text-transform: uppercase; font-size: 11.5px; letter-spacing: 0.6px;
    }
    /* In headers keep the column NAME uppercase (th default) but render the
       unit lowercase as written (rps / s/op / ms), so name vs unit read apart. */
    th .unit {
      text-transform: none; font-weight: 400; font-size: 10px;
      letter-spacing: 0; opacity: 0.8; margin-left: 5px;
    }
    th .op-note {
      text-transform: lowercase; font-weight: 400; font-size: 10px;
      letter-spacing: 0; opacity: 0.7; margin-left: 2px;
    }
    td { color: var(--text); }
    /* spec has no such operation at all -> not applicable */
    td.na-slash { color: var(--border); text-align: left; user-select: none; }
    tr:last-child td { border-bottom: none; }
    tbody tr:hover { background: rgba(9,105,218,0.06); }
    td strong { color: var(--accent); font-weight: 600; }
    .pass { color: var(--green); font-weight: 600; }
    .fail { color: var(--red); font-weight: 700; }
    .measured { color: var(--accent); font-weight: 600; }
    .notmeasured {
      color: #fff; background: var(--red); font-weight: 700;
      text-align: center; border-radius: 4px; font-size: 11.5px;
      letter-spacing: 0.5px;
    }
    tr.row-notmeasured { background: rgba(207,34,46,0.06) !important; }
    tr.row-notmeasured:hover { background: rgba(207,34,46,0.12) !important; }
    td .val { font-weight: 700; color: var(--text); font-size: 14px; }
    td .unit { color: var(--text-dim); font-size: 11px; font-weight: 400; margin-left: 3px; }
    td .op { color: var(--text-dim); font-weight: 400; }
    td .na { color: var(--text-dim); }
    td .yes { color: var(--green); font-weight: 700; }
    td .no { color: var(--red); font-weight: 700; }
    .summary-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
      gap: 16px; margin: 22px 0 8px;
    }
    .summary-card {
      background: var(--panel-2); padding: 18px 20px; border-radius: 10px;
      border: 1px solid var(--border); border-left: 4px solid var(--accent);
    }
    .summary-card.pass { border-left-color: var(--green); }
    .summary-card.fail { border-left-color: var(--red); }
    .summary-card h3 {
      margin: 0 0 10px; font-size: 12px; color: var(--text-dim);
      text-transform: uppercase; letter-spacing: 0.6px; font-weight: 600;
    }
    .summary-card .value { font-size: 30px; font-weight: 700; color: var(--text); }
    .src { color: var(--text-dim); font-size: 12px; }
    .legend {
      margin: 18px 0 2px; font-size: 12px; display: flex; gap: 18px;
      flex-wrap: wrap; align-items: center;
    }
    .legend span { white-space: nowrap; }
    .legend .hint { color: var(--text-dim); font-style: italic; margin-left: auto; }
    td.pass .val, td.pass { color: var(--green); }
    td.fail .val, td.fail { color: var(--red); }
    td.measured .val, td.measured { color: var(--accent); }
"""


def _nm_count(rows, want_cap: bool) -> int:
    return sum(1 for r in rows
               if r.result == "NOT MEASURED"
               and (r.result_type == "capability") == want_cap)


def styles():
    return _CSS


def render_section(summary: ReportSummary, rows: List[SpecRow],
                   actual: Dict[tuple, Dict[str, Any]],
                   route_fill_rows: Optional[List[Dict[str, Any]]] = None
                   ) -> str:
    """Document-free performance / scale / fill-rate / counter markup.

    Capability is rendered separately by render_capability.render_section.
    """
    route_fill_rows = route_fill_rows or []
    h = ['<div class="container">', '<h2>Performance &amp; Scale</h2>']

    h.append("<h2>Overview</h2><div class=\"summary-grid\">")
    h.append(_metric_card("Performance", summary.perf_pass, summary.perf_fail,
                          summary.perf_measured, summary.perf_total))
    h.append(_metric_card("Scale", summary.scale_pass, summary.scale_fail,
                          summary.scale_measured, summary.scale_total))
    h.append(_metric_card("Fill Rate", summary.fill_pass, summary.fill_fail,
                          summary.fill_measured, summary.fill_total))
    nm = _nm_count(rows, want_cap=False)
    if nm > 0:
        h.append(_card("NOT MEASURED", str(nm), "fail"))
    h.append("</div>")

    # Metric tables (incidental rows dropped). Each pivots operation -> columns.
    # Performance splits by direction: throughput (higher_better, rps in header)
    # vs latency/timing (lower_better, mixed s/op & ms).
    perf = [r for r in rows if r.result_type == "performance"]
    scale = [r for r in rows if r.result_type == "scale"]

    throughput = [r for r in perf if r.direction != "lower_better"]
    latency = [r for r in perf if r.direction == "lower_better"]
    flap = [r for r in throughput if r.spec_name == "route_flap"]
    throughput = [r for r in throughput if r.spec_name != "route_flap"]
    counters = [r for r in latency if '_counter_' in r.spec_name]
    op_lat = [r for r in latency if '_counter_' not in r.spec_name]

    h.append(_legend())
    if throughput:
        h.append(_pivot_table("Throughput (entries/s)", throughput,
                              header_unit="entries/s"))
    if flap:
        h.append(_pivot_table("Route Flap (entries/s)", flap,
                              header_unit="entries/s"))
    if counters:
        h.append(_counter_perf_table(counters))
    if op_lat:
        h.append(_pivot_table("Operation Latency (ms)", op_lat,
                              header_unit="ms"))
    if scale:
        h.append(_pivot_table("Scale (capacity)", scale))
    if route_fill_rows:
        h.append(_fill_rate_table(route_fill_rows, actual))

    h.append("</div>")
    return "\n".join(h)


def _card(title, value, cls=""):
    return (f"<div class=\"summary-card {_html(cls)}\"><h3>{_html(title)}</h3>"
            f"<div class=\"value\">{_html(value)}</div></div>")


def _metric_label_value(label, npass, nfail, nmeasured, total):
    """Decide a category's summary label/value/css by phase.

    - judged (has pass or fail)         -> "{label} PASS", n/total, green/red
    - collect-only (only measured)      -> "{label} MEASURED", measured/total
    - nothing measured at all           -> "{label} NOT MEASURED", 0/total
    """
    if total == 0:
        return None
    if npass > 0 or nfail > 0:
        cls = "pass" if nfail == 0 else "fail"
        return (f"{label} PASS", f"{npass}/{total}", cls)
    if nmeasured > 0:
        return (f"{label} MEASURED", f"{nmeasured}/{total}", "")
    # all NOT MEASURED
    return (f"{label} NOT MEASURED", f"0/{total}", "fail")


def _metric_card(label, npass, nfail, nmeasured, total):
    """Phase-aware summary card."""
    lv = _metric_label_value(label, npass, nfail, nmeasured, total)
    if lv is None:
        return ""
    title, value, cls = lv
    return _card(title, value, cls)


def _metric_label(r) -> str:
    """Render one metric plus the case/scenario that produced it."""
    label = f"<strong>{_html(r.spec_name)}</strong>"
    provenance = []
    if r.test_class:
        provenance.append(str(r.test_class))
    if r.scenario:
        provenance.append(str(r.scenario))
    if r.occurrence:
        provenance.append("measurement {}".format(r.occurrence + 1))
    if provenance:
        label += '<span class="src">{}</span>'.format(
            _html(' · '.join(provenance)))
    return label


def _num_unit(num_str: str, unit: str) -> str:
    """Self-contained value: bold number + dimmed small unit suffix."""
    if not unit:
        return f"<span class=\"val\">{_html(num_str)}</span>"
    return (f"<span class=\"val\">{_html(num_str)}</span>"
            f"<span class=\"unit\">{_html(unit)}</span>")


# Operation column ordering: create-like first, remove-like last.
_OP_ORDER = ["", "create", "add", "learn", "verify", "read", "get", "set",
             "update", "group_create", "member_create",
             "group_remove", "member_remove", "remove", "delete"]

# Clarifying note appended to a column header (kept lowercase / dim in CSS).
_OP_NOTE = {"set": "update"}


def _op_sort_key(op):
    if op in _OP_ORDER:
        return (_OP_ORDER.index(op), op)
    return (len(_OP_ORDER), op)


def _cell(r, header_unit) -> str:
    """One value cell, colored by its own result; detail in tooltip.

    When the unit is folded into the table header (header_unit set), the cell
    shows a bare number; otherwise the unit travels with the value.
    """
    if r.result == "NOT MEASURED":
        inner = "<span class=\"na\">n/m</span>"
    elif isinstance(r.value, (int, float)):
        if r.result_type == "capability":
            inner = ("<span class=\"yes\">✓ Supported</span>" if r.value == 1
                     else "<span class=\"no\">✗ Not supported</span>")
        elif r.result_type == "fill_rate":
            inner = f"<span class=\"val\">{r.value:.2f}%</span>"
        elif header_unit:
            inner = f"<span class=\"val\">{_fmt_num(r.value)}</span>"
        else:
            inner = _num_unit(_fmt_num(r.value), r.unit)
    else:
        inner = "<span class=\"na\">—</span>"
    colorcls = {"PASS": "pass", "FAIL": "fail",
                "MEASURED": "measured"}.get(r.result, "")
    tip = _tooltip_full(r)
    ta = f" title=\"{_html(tip)}\"" if tip else ""
    return f"<td class=\"{colorcls}\"{ta}>{inner}</td>"


def _tooltip_full(r) -> str:
    """Per-cell detail facts and source case."""
    bits = []
    for key, label in (('attempted_count', 'attempted'),
                       ('completed_count', 'completed'),
                       ('observed_count', 'observed')):
        value = r.details.get(key)
        if isinstance(value, (int, float)):
            bits.append('%s %s' % (label, _fmt_num(value)))
    duration = r.details.get('duration_seconds')
    if isinstance(duration, (int, float)):
        bits.append('duration %.3f s' % duration)
    if r.details.get('scenario'):
        bits.append('scenario %s' % r.details['scenario'])
    if r.details.get('error'):
        bits.append('error %s' % r.details['error'])
    if r.test_class:
        bits.append(f"source {r.test_class}")
    return " | ".join(bits)


def _legend() -> str:
    return ("<div class=\"legend\">"
            "<span class=\"pass\">✓ PASS</span>"
            "<span class=\"fail\">✗ FAIL</span>"
            "<span class=\"measured\">▫ MEASURED</span>"
            "<span class=\"na\">⛔ NOT MEASURED</span>"
            "<span class=\"hint\">hover a cell for details / source</span></div>")


# fill-rate spec -> the scale spec(s) carrying its capacity
_CAPACITY_OF = {
    'ipv4_route_fill_rate':      ('ipv4_prefix',),
    'ipv6_route_fill_rate':      ('ipv6_prefix',),
    'ipv4_ipv6_route_fill_rate': ('ipv4_prefix', 'ipv6_prefix'),
    'fdb_fill_rate':             ('fdb_entry',),
}

_CAPACITY_NOTE = ("scale = SAI_SWITCH_ATTR_AVAILABLE_* , i.e. entries still "
                  "available; SAI exposes no hardware max for these tables. "
                  "A mixed v4/v6 case shares one route table, so its scale is "
                  "the smaller of the two available counts, not their sum")


def _capacity_of(spec_name, actual, test_class=None):
    """Smallest measured scale spec backing this fill-rate spec.

    v4 and v6 available counts are two views of one shared route table, so the
    conservative single value is the basis -- summing them would claim a
    capacity no chip can deliver.

    Returns (scale, contributing specs); scale is None when none was measured.
    """
    scale, used = None, []
    for cap_spec in _CAPACITY_OF.get(spec_name, ()):
        values = []
        for key, measured in actual.items():
            if key[0:2] != (cap_spec, ""):
                continue
            if test_class and key[2] != test_class:
                continue
            value = measured.get("value")
            if isinstance(value, (int, float)):
                values.append(value)
        if values:
            value = min(values)
            scale = value if scale is None else min(scale, value)
            used.append(cap_spec)
    return scale, used


def _fill_rate_table(rfrows, actual) -> str:
    """Fill rate dimensioned by deployment scenario (test case).

    Covers route fill rates and fdb_fill_rate alike. One row per case:
    scenario | capacity | installed scale | fill rate (+ attempted in tooltip).
    The fill cell is colored by its own result.
    """
    out = ["<h2>Fill Rate &amp; Scale</h2>",
           "<div class=\"table-scroll\"><table><thead><tr>",
           "<th>Scenario (case)</th>",
           f"<th title=\"{_CAPACITY_NOTE}\">Scale</th>",
           "<th>Installed</th><th>Fill rate</th>",
           "</tr></thead><tbody>"]
    # sequential before random: that is the order the case runs them in.
    rank = {None: 0, "sequential": 1, "random": 2}
    for r in sorted(rfrows, key=lambda x: (x["spec_name"], x["test_class"],
                                           rank.get(x.get("order"), 3))):
        res = r["result"]
        colorcls = {"PASS": "pass", "FAIL": "fail",
                    "MEASURED": "measured"}.get(res, "")
        fill = (f"{r['fill']:.2f}%" if isinstance(r["fill"], (int, float))
                else "—")
        inst = (_fmt_num(r["installed"])
                if isinstance(r["installed"], (int, float)) else "—")
        cap, cap_src = _capacity_of(
            r["spec_name"], actual, test_class=r["test_class"])
        if cap is None:
            cap_cell = "<td><span class=\"na\">—</span></td>"
        else:
            src = ', '.join(cap_src)
            if len(cap_src) > 1:
                src = "min of " + src
            cap_cell = (f"<td title=\"from {_html(src)}\">"
                        f"<span class=\"val\">{_fmt_num(cap)}</span></td>")
        # attempted (the fill-rate denominator) is derivable from fill% and
        # installed, so it lives in the tooltip rather than its own column.
        att = (f"attempted {_fmt_num(r['attempted'])}"
               if isinstance(r["attempted"], (int, float)) else "")
        ta = f" title=\"{att}\"" if att else ""
        scenario = r["test_class"] or "—"
        if r.get("order"):
            scenario += f" ({r['order']})"
        out.append(f"<tr{ta}><td><strong>{_html(scenario)}</strong></td>")
        out.append(cap_cell)
        out.append(f"<td><span class=\"val\">{inst}</span></td>")
        out.append(f"<td class=\"{colorcls}\"><span class=\"val\">{fill}</span></td></tr>")
    out.append("</tbody></table></div>")
    return "\n".join(out)


def _counter_perf_table(rows) -> str:
    """Counter read/clear cost as TOTAL elapsed time per scenario (ms).

    Counter reads are sub-millisecond per operation, so the report shows the
    total time to read or clear all observed counters once. Total time comes
    from `details.duration_seconds`; the observed count comes from the same
    details object.
    """
    def _obj(spec_name):
        base = spec_name.replace("_counter_read", "")
        return " ".join(w.upper() if w in ("acl", "pg") else w
                        for w in base.split("_"))

    def _verb(op):
        return {"read": "Read", "clear": "Clear"}.get(op, (op or "read").capitalize())

    ordered = sorted(rows, key=lambda r: (r.spec_name,
                                          0 if r.operation == "read" else 1))
    out = ["<h2>Counter Performance</h2>"
           "<div class=\"table-scroll\"><table><thead><tr>"
           "<th>Counter Performance</th><th>Time</th></tr></thead><tbody>"]
    for r in ordered:
        observed = r.details.get('observed_count')
        cnt = (f"{int(observed)} "
               if isinstance(observed, (int, float)) and observed else "")
        desc = f"{_verb(r.operation)} {cnt}{_obj(r.spec_name)} counters"
        provenance = []
        if r.test_class:
            provenance.append(str(r.test_class))
        if r.scenario:
            provenance.append(str(r.scenario))
        if r.occurrence:
            provenance.append("measurement {}".format(r.occurrence + 1))
        if provenance:
            desc += " ({})".format(" · ".join(provenance))
        colorcls = {"PASS": "pass", "FAIL": "fail",
                    "MEASURED": "measured"}.get(r.result, "")
        if r.result == "NOT MEASURED":
            cell = '<td class="fail"><span class="na">n/m</span></td>'
        elif isinstance(r.details.get('duration_seconds'), (int, float)):
            cell = (f'<td class="{colorcls}"><span class="val">'
                    f"{r.details['duration_seconds'] * 1000:.1f} ms</span></td>")
        else:
            cell = '<td><span class="na">—</span></td>'
        out.append(f"<tr><td>{_html(desc)}</td>{cell}</tr>")
    out.append("</tbody></table></div>")
    return "\n".join(out)


def _pivot_table(title: str, rows, header_unit=None, collapse=False) -> str:
    """Pivot operation -> columns: one row per spec, one cell per operation.

    e.g. ecmp_group_scale's create & remove become two cells on one row. Each
    cell is colored by its own three-state result. Specs with no operation
    (scale capacity) collapse to a single Measured column. Pass collapse=True
    for one-value-per-spec metrics (fill_rate / capability) where operation is
    not a meaningful axis -- they render a single Measured column regardless of op.
    """
    by_spec = {}
    for r in rows:
        identity = (r.spec_name, r.test_class, r.scenario, r.occurrence)
        by_spec.setdefault(identity, {})[r.operation] = r
    ops = sorted({r.operation for r in rows}, key=_op_sort_key)
    single = collapse or (ops == [""])

    hdr = (f"Measured ({header_unit})" if (single and header_unit) else "Measured")
    out = [f"<h2>{_html(title)}</h2><div class=\"table-scroll\">"
           "<table><thead><tr><th>Metric</th>"]
    if single:
        out.append(f"<th>{_html(hdr)}</th>")
    else:
        for op in ops:
            label = _html(op if op else "—")
            note = _OP_NOTE.get(op)
            if note:
                label += f"<span class=\"op-note\">({_html(note)})</span>"
            if header_unit:
                label += f"<span class=\"unit\">{_html(header_unit)}</span>"
            out.append(f"<th>{label}</th>")
    out.append("</tr></thead><tbody>")

    for identity in sorted(by_spec):
        opmap = by_spec[identity]
        representative = next(iter(opmap.values()))
        all_nm = all(x.result == "NOT MEASURED" for x in opmap.values())
        rowcls = "row-notmeasured" if all_nm else ""
        out.append(
            f"<tr class=\"{rowcls}\"><td>{_metric_label(representative)}</td>")
        col_ops = [""] if single else ops
        for op in col_ops:
            r = opmap.get(op) if not single else (
                opmap.get("") or next(iter(opmap.values())))
            if r is None:
                # This spec has no such operation at all -> N/A (slash),
                # distinct from a declared-but-not-run cell (red n/m).
                out.append("<td class=\"na-slash\">／</td>")
            else:
                out.append(_cell(r, header_unit))
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "\n".join(out)
