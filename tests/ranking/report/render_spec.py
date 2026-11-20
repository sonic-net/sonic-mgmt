#!/usr/bin/env python3
"""
SAI Test Report Generator (metric-centric)

Generates an HTML report organized by metric, not by test case. The registry's
explicit ``metric_type`` selects the report section; ``display_name`` and
``unit`` control the user-facing label and value unit.

The report is driven by the measured spec results: every spec the run actually
recorded becomes a row.

Test-case pass/fail belongs to the Test Results section, not here. This module
accepts validated in-memory result documents and renders spec values only.
"""

from dataclasses import dataclass, replace
from html import escape
from typing import Dict, List, Optional, Any


_KNOWN_METRIC_TYPES = ("throughput", "latency", "counter", "scale", "fill_rate")


def _html(value) -> str:
    return escape(str(value), quote=True)


def _norm_metric_type(metric_type: Optional[str]) -> str:
    """Validate one explicit report metric type."""
    if metric_type not in _KNOWN_METRIC_TYPES:
        raise ValueError("unknown registry metric_type: %r" % metric_type)
    return metric_type


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
    unit: str
    direction: str            # higher_better | lower_better | equal
    value: Optional[float]
    details: Dict[str, Any]
    result: str               # MEASURED | NOT MEASURED
    test_class: str           # source case (provenance only; may be "")
    scenario: str = ""       # case-defined measurement scenario
    occurrence: int = 0      # repeated measurement within the same scenario
    display_name: str = ""   # human-readable report label
    metric_type: str = ""    # throughput | latency | counter | scale | fill_rate


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
    for spec_name, definition in registry.items():
        if spec_name.startswith("_") or not isinstance(definition, dict):
            continue
        _norm_metric_type(definition.get("metric_type"))
        operations = definition.get("operations") or [None]
        for operation in operations:
            definitions[(spec_name, _norm_op(operation))] = definition
    return definitions


def build_fill_rate_rows(results, definitions) -> List[Dict[str, Any]]:
    """Build every fill-rate row directly from per-case result documents.

    Unlike build_actual_specs, this does not dedupe by spec and operation.
    Fill-rate membership comes only from the registry's metric_type.
    """
    out: List[Dict[str, Any]] = []
    for data in results:
        tc = data.get("case", data.get("test_class", ""))
        for spec in data.get("spec_results", []):
            spec = _report_spec(spec)
            name = spec.get("spec_name", "")
            definition = definitions.get((name, _norm_op(spec.get("operation"))), {})
            if definition.get("metric_type") != "fill_rate":
                continue
            if not definition.get("include_in_report", True):
                continue
            details = spec.get("details") or {}
            out.append({
                "test_class": tc,
                "spec_name": name,
                "display_name": definition.get("display_name", name),
                "fill": spec.get("value"),
                "installed": details.get(
                    "success_route_cnt", details.get("completed_count")),
                "order": details.get("order", details.get("scenario")),
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

    Definitions marked ``include_in_report: false`` are collected but omitted
    from the report.
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
        if not registered.get("include_in_report", True):
            continue
        metric_type = _norm_metric_type(registered.get("metric_type"))
        measured_provenance.setdefault(spec_name, set()).add(
            (test_class, scenario, occurrence))
        measured = actual[key]
        direction = registered.get("direction", "higher_better")
        value = measured.get("value")
        threshold = measured.get("threshold")
        rows.append(SpecRow(
            spec_name=spec_name, operation=operation,
            unit=registered.get("unit", ""), direction=direction,
            value=value, details=measured.get("details", {}),
            result=_decide_result(value, threshold, direction),
            test_class=test_class, scenario=scenario,
            occurrence=occurrence,
            display_name=registered.get("display_name", spec_name),
            metric_type=metric_type))

    for spec_name, operation in sorted(expected):
        registered = definitions.get((spec_name, operation), {})
        if not registered.get("include_in_report", True):
            continue
        metric_type = _norm_metric_type(registered.get("metric_type"))
        provenances = measured_provenance.get(spec_name) or {("", "", 0)}
        for test_class, scenario, occurrence in sorted(provenances):
            if (spec_name, operation, test_class, scenario, occurrence) in actual:
                continue
            rows.append(SpecRow(
                spec_name=spec_name, operation=operation,
                unit=registered.get("unit", ""),
                direction=registered.get("direction", "higher_better"),
                value=None, details={}, result="NOT MEASURED",
                test_class=test_class, scenario=scenario,
                occurrence=occurrence,
                display_name=registered.get("display_name", spec_name),
                metric_type=metric_type))

    return rows


def summarize(rows: List[SpecRow]) -> ReportSummary:
    s = ReportSummary()
    for (metric_type, _spec_name, _operation), result in (
            _unique_metric_results(rows).items()):
        if metric_type in ("throughput", "latency", "counter"):
            s.perf_total += 1
            if result == "PASS":
                s.perf_pass += 1
            elif result == "FAIL":
                s.perf_fail += 1
            elif result == "MEASURED":
                s.perf_measured += 1
        elif metric_type == "scale":
            s.scale_total += 1
            if result == "PASS":
                s.scale_pass += 1
            elif result == "FAIL":
                s.scale_fail += 1
            elif result == "MEASURED":
                s.scale_measured += 1
        elif metric_type == "fill_rate":
            s.fill_total += 1
            if result == "PASS":
                s.fill_pass += 1
            elif result == "FAIL":
                s.fill_fail += 1
            elif result == "MEASURED":
                s.fill_measured += 1
    return s


def _combined_result(rows) -> str:
    """Conservatively combine statuses for one metric/operation cell."""
    results = {row.result for row in rows}
    if "FAIL" in results:
        return "FAIL"
    if "PASS" in results:
        return "PASS"
    if "MEASURED" in results:
        return "MEASURED"
    return "NOT MEASURED"


def _unique_metric_results(rows):
    """Return one status per metric type, metric, and operation."""
    grouped = {}
    for row in rows:
        grouped.setdefault(
            (row.metric_type, row.spec_name, row.operation), []).append(row)
    return {key: _combined_result(group) for key, group in grouped.items()}


def _aggregate_metric_rows(rows, reducer) -> List[SpecRow]:
    """Build display-only rows without discarding raw observations.

    `rows` remains the source of truth. The returned rows intentionally omit
    case/scenario provenance because that evidence stays in per-case JSON and
    logs rather than expanding the compact report table.
    """
    grouped = {}
    for row in rows:
        grouped.setdefault((row.spec_name, row.operation), []).append(row)

    aggregated = []
    for key in sorted(grouped):
        group = grouped[key]
        representative = group[0]
        valid = [row for row in group
                 if row.result != "NOT MEASURED"
                 and isinstance(row.value, (int, float))]
        value = reducer([row.value for row in valid]) if valid else None
        details = {}
        counts = sorted({row.details.get("count") for row in valid
                         if isinstance(row.details.get("count"), (int, float))})
        if len(counts) == 1:
            details["count"] = counts[0]
        elif counts:
            details["count_range"] = (counts[0], counts[-1])
        aggregated.append(SpecRow(
            spec_name=representative.spec_name,
            operation=representative.operation,
            unit=representative.unit,
            direction=representative.direction,
            value=value,
            details=details,
            result=_combined_result(valid) if valid else "NOT MEASURED",
            test_class="",
            scenario="",
            occurrence=0,
            display_name=representative.display_name,
            metric_type=representative.metric_type,
        ))
    return aggregated


def _mean(values):
    return sum(values) / len(values)


_ROUTE_FLAP_DISPLAY = {
    "group_create": ("route_flap_group", "Route flap — group", "create"),
    "group_remove": ("route_flap_group", "Route flap — group", "remove"),
    "member_create": ("route_flap_member", "Route flap — member", "create"),
    "member_remove": ("route_flap_member", "Route flap — member", "remove"),
}


def _normalize_performance_rows(rows):
    """Map route-flap implementation operations onto the common matrix."""
    normalized = []
    for row in rows:
        if row.spec_name != "route_flap":
            normalized.append(row)
            continue
        identity = _ROUTE_FLAP_DISPLAY.get(row.operation)
        if identity is None:
            raise ValueError(
                "unknown route_flap operation: %s" % row.operation)
        spec_name, display_name, operation = identity
        normalized.append(replace(
            row, spec_name=spec_name, display_name=display_name,
            operation=operation))
    return normalized


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
    h3 {
      color: var(--text); font-size: 14px; margin: 22px 0 4px;
    }
    h3 .section-note {
      color: var(--text-dim); font-weight: 400; font-size: 12px;
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
    /* Keep column names uppercase while rendering units as registered. */
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
    td .cell-detail {
      display: block; color: var(--text-dim); font-size: 11px;
      font-weight: 400; margin-top: 2px;
    }
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
    .report-note { color: var(--text-dim); font-size: 12px; margin: 18px 0 0; }
    td.pass .val, td.pass { color: var(--green); }
    td.fail .val, td.fail { color: var(--red); }
    td.measured .val, td.measured { color: var(--accent); }
    .scale-toggle {
      width: 100%; display: inline-flex; align-items: center; gap: 7px;
      border: 0; padding: 0; background: transparent; color: var(--accent);
      font: inherit; font-weight: 600; text-align: left; cursor: pointer;
    }
    .scale-toggle:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .scale-arrow { color: var(--text-dim); transition: transform 0.15s ease; }
    .scale-toggle[aria-expanded="true"] .scale-arrow { transform: rotate(90deg); }
    .scenario-count {
      color: var(--text-dim); font-size: 11px; font-weight: 400;
      margin-left: auto; white-space: nowrap;
    }
    .scale-detail-row > td { background: var(--panel-2); padding: 0 14px 12px 34px; }
    .scale-detail-row table { margin: 0; background: var(--panel); }
    .scale-detail-row td { background: var(--panel); }
    @media (prefers-reduced-motion: reduce) {
      .scale-arrow { transition: none; }
    }
"""


def _nm_count(rows, want_cap: bool) -> int:
    return sum(
        1 for (metric_type, _spec_name, _operation), result
        in _unique_metric_results(rows).items()
        if result == "NOT MEASURED"
        and (metric_type == "capability") == want_cap)


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

    throughput = [r for r in rows if r.metric_type == "throughput"]
    counters = [r for r in rows if r.metric_type == "counter"]
    op_lat = [r for r in rows if r.metric_type == "latency"]
    scale = [r for r in rows if r.metric_type == "scale"]

    h.append(_legend())
    performance = throughput + counters + op_lat
    if performance:
        h.append(_performance_table(performance))
    if scale or route_fill_rows:
        h.append(_scale_table(scale, route_fill_rows, actual))

    h.append(
        '<p class="report-note">Summary and tables are grouped by metric and '
        'operation. Raw observations remain in per-case result JSON and logs.'
        '</p>')

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
    label = f"<strong>{_html(r.display_name or r.spec_name)}</strong>"
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


def _operation_label(operation):
    """Turn a registry operation identifier into a compact table heading."""
    return operation.replace("_", " ").capitalize() if operation else "—"


def _cell(r, header_unit) -> str:
    """One value cell, colored by its own result; detail in tooltip.

    When the unit is folded into the table header (header_unit set), the cell
    shows a bare number; otherwise the unit travels with the value.
    """
    if r.result == "NOT MEASURED":
        inner = "<span class=\"na\">n/m</span>"
    elif isinstance(r.value, (int, float)):
        if r.metric_type == "capability":
            inner = ("<span class=\"yes\">✓ Supported</span>" if r.value == 1
                     else "<span class=\"no\">✗ Not supported</span>")
        elif r.metric_type == "fill_rate":
            inner = f"<span class=\"val\">{r.value:.2f}%</span>"
        elif header_unit:
            inner = f"<span class=\"val\">{_fmt_num(r.value)}</span>"
        else:
            inner = _num_unit(_fmt_num(r.value), r.unit)
    else:
        inner = "<span class=\"na\">—</span>"
    if r.metric_type == "counter":
        count = r.details.get("count")
        count_range = r.details.get("count_range")
        if isinstance(count, (int, float)):
            inner += (f'<span class="cell-detail">{_fmt_num(count)} '
                      'counters</span>')
        elif (isinstance(count_range, tuple) and len(count_range) == 2):
            inner += (
                f'<span class="cell-detail">{_fmt_num(count_range[0])}–'
                f'{_fmt_num(count_range[1])} counters</span>')
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


def _scale_table(scale_rows, fill_rows, actual) -> str:
    """Render one conservative summary row per scale specification.

    Fill-rate observations remain available as expandable evidence instead of
    repeating the same user-facing spec name for every case and order.
    """
    aggregated = _aggregate_metric_rows(scale_rows, max)
    units = {row.spec_name: row.unit for row in aggregated}
    replaced_scale_specs = set()
    for fill in fill_rows:
        backing = _CAPACITY_OF.get(fill["spec_name"], ())
        if len(backing) == 1:
            replaced_scale_specs.update(backing)

    fill_groups = {}
    for fill in fill_rows:
        key = (fill["spec_name"], fill.get("display_name") or fill["spec_name"])
        fill_groups.setdefault(key, []).append(fill)

    entries = []
    for row in aggregated:
        if row.spec_name not in replaced_scale_specs:
            entries.append((
                (row.display_name or row.spec_name).casefold(), "scale",
                len(entries), row))
    for (_spec_name, display_name), group in fill_groups.items():
        entries.append((display_name.casefold(), "fill", len(entries), group))

    out = ["<h2>Scale</h2>",
           "<div class=\"table-scroll\"><table><thead><tr>",
           "<th>Spec name</th>",
           f"<th title=\"{_CAPACITY_NOTE}\">Reported scale</th>",
           "<th>Installed</th><th>Fill rate</th>",
           "</tr></thead><tbody>"]
    detail_index = 0
    for _name_key, kind, _entry_index, item in sorted(entries):
        if kind == "scale":
            row = item
            name = row.display_name or row.spec_name
            if isinstance(row.value, (int, float)):
                scale = _num_unit(_fmt_num(row.value), row.unit)
                scale_class = {"PASS": "pass", "FAIL": "fail",
                               "MEASURED": "measured"}.get(row.result, "")
            else:
                scale = '<span class="na">n/m</span>'
                scale_class = "fail"
            out.append(
                f"<tr><td><strong>{_html(name)}</strong></td>"
                f'<td class="{scale_class}">{scale}</td>'
                '<td class="na-slash">／</td>'
                '<td class="na-slash">／</td></tr>')
            continue

        group = item
        fill = min(group, key=lambda candidate: (
            candidate.get("fill")
            if isinstance(candidate.get("fill"), (int, float)) else float("inf"),
            candidate.get("installed")
            if isinstance(candidate.get("installed"), (int, float)) else float("inf"),
            candidate.get("test_class", ""),
        ))
        result = fill.get("result", "MEASURED")
        colorcls = {"PASS": "pass", "FAIL": "fail",
                    "MEASURED": "measured"}.get(result, "")
        name = fill.get("display_name") or fill["spec_name"]
        cap, cap_src = _capacity_of(fill["spec_name"], actual)
        cap_unit = next(
            (units.get(spec_name, "") for spec_name in cap_src), "")
        if cap is None:
            cap_cell = '<td><span class="na">—</span></td>'
        else:
            source = ', '.join(cap_src)
            if len(cap_src) > 1:
                source = "min of " + source
            cap_cell = (
                f'<td title="from {_html(source)}">'
                f'{_num_unit(_fmt_num(cap), cap_unit)}</td>')
        installed = fill.get("installed")
        installed_text = (
            _fmt_num(installed)
            if isinstance(installed, (int, float)) else "—")
        fill_value = fill.get("fill")
        fill_text = (
            f"{fill_value:.2f}%"
            if isinstance(fill_value, (int, float)) else "—")
        detail_id = "scale-scenarios-{}".format(detail_index)
        detail_index += 1
        out.append(
            '<tr><td><button type="button" class="scale-toggle" '
            f'aria-expanded="false" aria-controls="{detail_id}">'
            '<span class="scale-arrow" aria-hidden="true">›</span>'
            f'<span>{_html(name)}</span><span class="scenario-count">'
            f'{len(group)} scenarios</span></button></td>')
        out.append(cap_cell)
        out.append(
            f'<td><span class="val">{installed_text}</span></td>'
            f'<td class="{colorcls}"><span class="val">'
            f'{fill_text}</span></td></tr>')
        out.append(
            f'<tr id="{detail_id}" class="scale-detail-row" hidden>'
            '<td colspan="4"><div class="table-scroll"><table>'
            '<thead><tr><th>Scenario</th><th>Order</th>'
            '<th>Installed</th><th>Fill rate</th></tr></thead><tbody>')
        order_rank = {"sequential": 0, "random": 1}
        for evidence in sorted(group, key=lambda candidate: (
                candidate.get("test_class", "").casefold(),
                order_rank.get(candidate.get("order"), 2))):
            test_class = evidence.get("test_class", "")
            order = evidence.get("order")
            if not order and "mask" in test_class.casefold():
                order = "mask"
            installed = evidence.get("installed")
            installed_detail = (
                _fmt_num(installed)
                if isinstance(installed, (int, float)) else "—")
            fill_value = evidence.get("fill")
            fill_detail = (
                f"{fill_value:.2f}%"
                if isinstance(fill_value, (int, float)) else "—")
            out.append(
                f'<tr><td>{_html(test_class)}</td><td>{_html(order or "—")}</td>'
                f'<td><span class="val">{installed_detail}</span></td>'
                f'<td><span class="val">{fill_detail}</span></td></tr>')
        out.append("</tbody></table></div></td></tr>")
    out.append("</tbody></table></div>")
    if fill_groups:
        out.append("""
<script>
document.addEventListener("click", function (event) {
  var button = event.target.closest(".scale-toggle");
  if (!button) return;
  var detail = document.getElementById(button.getAttribute("aria-controls"));
  if (!detail) return;
  var open = button.getAttribute("aria-expanded") === "true";
  button.setAttribute("aria-expanded", String(!open));
  detail.hidden = open;
});
</script>""")
    return "\n".join(out)


def _performance_table(rows) -> str:
    """Render rate and duration measurements without mixing their units."""
    throughput = [row for row in rows if row.metric_type == "throughput"]
    timing = [row for row in rows if row.metric_type in ("counter", "latency")]
    out = ["<h2>Performance</h2>"]
    if throughput:
        out.append(_throughput_table(throughput))
    if timing:
        out.append(_latency_table(timing))
    return "\n".join(out)


def _throughput_table(rows) -> str:
    """Render throughput operations in an rps-only comparison matrix."""
    aggregated = _aggregate_metric_rows(
        _normalize_performance_rows(rows), _mean)
    by_spec = {}
    for row in aggregated:
        by_spec.setdefault(row.spec_name, {})[row.operation] = row
    operations = sorted({row.operation for row in aggregated}, key=_op_sort_key)
    out = [
        '<h3>Throughput <span class="section-note">'
        '(rps · higher is better)</span></h3>',
        '<div class="table-scroll"><table><thead><tr><th>Spec name</th>',
    ]
    for operation in operations:
        label = "Update" if operation == "set" else _operation_label(operation)
        out.append(f"<th>{_html(label)}</th>")
    out.append("</tr></thead><tbody>")
    for spec_name in sorted(by_spec):
        operation_rows = by_spec[spec_name]
        representative = next(iter(operation_rows.values()))
        row_class = (
            ' class="row-notmeasured"'
            if all(row.result == "NOT MEASURED"
                   for row in operation_rows.values()) else "")
        out.append(
            f"<tr{row_class}><td>{_metric_label(representative)}</td>")
        for operation in operations:
            row = operation_rows.get(operation)
            out.append(_cell(row, "rps") if row is not None
                       else '<td class="na-slash">／</td>')
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "\n".join(out)


def _latency_table(rows) -> str:
    """Render duration measurements as one operation per row."""
    normalized = [
        replace(row, operation="get")
        if row.metric_type == "counter" and row.operation == "read" else row
        for row in rows
    ]
    aggregated = _aggregate_metric_rows(normalized, _mean)
    ordered = sorted(aggregated, key=lambda row: (
        (row.display_name or row.spec_name).casefold(),
        _op_sort_key(row.operation)))
    out = [
        '<h3>Operation latency <span class="section-note">'
        '(ms · lower is better)</span></h3>',
        '<div class="table-scroll"><table><thead><tr><th>Spec name</th>'
        '<th>Operation</th><th>Time</th><th>Workload</th>'
        '</tr></thead><tbody>',
    ]
    for row in ordered:
        operation = _operation_label(row.operation).upper()
        if row.result == "NOT MEASURED":
            time_cell = '<td class="fail"><span class="na">n/m</span></td>'
        elif isinstance(row.value, (int, float)):
            colorcls = {"PASS": "pass", "FAIL": "fail",
                        "MEASURED": "measured"}.get(row.result, "")
            time_cell = (
                f'<td class="{colorcls}">{_num_unit(_fmt_num(row.value), row.unit)}'
                '</td>')
        else:
            time_cell = '<td><span class="na">—</span></td>'
        suffix = "counters" if row.metric_type == "counter" else "operations"
        count = row.details.get("count")
        count_range = row.details.get("count_range")
        if isinstance(count, (int, float)):
            workload = "{} {}".format(_fmt_num(count), suffix)
        elif isinstance(count_range, tuple) and len(count_range) == 2:
            workload = "{}–{} {}".format(
                _fmt_num(count_range[0]), _fmt_num(count_range[1]), suffix)
        else:
            workload = "—"
        out.append(
            f'<tr><td><strong>{_html(row.display_name or row.spec_name)}</strong>'
            f'</td><td>{_html(operation)}</td>{time_cell}'
            f'<td>{_html(workload)}</td></tr>')
    out.append("</tbody></table></div>")
    return "\n".join(out)


def _pivot_table(title: str, rows, header_unit=None, collapse=False,
                 aggregation=None) -> str:
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

    if aggregation == "maximum":
        hdr = "Maximum measured"
    else:
        hdr = (f"Measured ({header_unit})"
               if (single and header_unit) else "Measured")
    out = [f"<h2>{_html(title)}</h2><div class=\"table-scroll\">"
           "<table><thead><tr><th>Spec name</th>"]
    if single:
        out.append(f"<th>{_html(hdr)}</th>")
    else:
        for op in ops:
            label = _html(_operation_label(op))
            if aggregation == "average":
                label += " average"
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
