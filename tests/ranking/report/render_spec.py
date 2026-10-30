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

Test-case pass/fail lives in result.txt, NOT here. This report only reports
each spec metric's measured value.

Usage:
    python3 sai_report.py --json-dir per_case_json/ --output report.html \
        --format html --asic-type th6 --build-id 53
"""

import argparse
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


_KNOWN_TYPES = ("performance", "scale", "fill_rate", "capability", "incidental")


def _norm_type(result_type: Optional[str]) -> str:
    """Validate a registry result type."""
    if result_type not in _KNOWN_TYPES:
        raise ValueError("unknown registry result_type: %r" % result_type)
    return result_type


def _norm_op(operation) -> str:
    return operation if operation else ""


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
    cap_pass: int = 0
    cap_fail: int = 0
    cap_measured: int = 0
    cap_total: int = 0
    fill_pass: int = 0
    fill_fail: int = 0
    fill_measured: int = 0
    fill_total: int = 0
    not_measured: int = 0
    build_id: Optional[str] = None
    asic_type: Optional[str] = None
    timestamp: str = ""


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_actual_specs(json_dir: str) -> Dict[tuple, Dict[str, Any]]:
    """Load all spec_results from per-case JSON files.

    Returns a dict keyed by (spec_name, operation) -> enriched spec dict
    (the spec fields plus 'test_class' for provenance). ptf_results.json is
    skipped (it is case-level, not spec-level).
    """
    actual = {}
    json_path = Path(json_dir)
    if not json_path.exists():
        print(f"Warning: JSON directory {json_dir} does not exist")
        return actual

    for json_file in sorted(json_path.glob("*.json")):
        if json_file.name == "ptf_results.json":
            continue
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error loading {json_file}: {e}")
            continue

        test_class = data.get("test_class", "")
        for spec in data.get("spec_results", []):
            key = (spec.get("spec_name", "unknown"), _norm_op(spec.get("operation")))
            enriched = dict(spec)
            enriched["test_class"] = test_class
            # Last writer wins if the same (spec, op) appears in multiple
            # cases; they describe the same metric so either value serves.
            actual[key] = enriched

    return actual


def load_registry_definitions(json_dir: str) -> Dict[tuple, Dict[str, Any]]:
    """Load all metric definitions, including non-rendered incidental specs."""
    path = Path(json_dir) / "spec_registry.json"
    if not path.exists():
        raise ValueError("spec registry %s does not exist" % path)
    with open(path, 'r') as f:
        registry = json.load(f)

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


def load_registered_specs(json_dir: str) -> Dict[tuple, Dict[str, Any]]:
    """Expand renderable registry definitions into expected report cells."""
    return {key: definition
            for key, definition in load_registry_definitions(json_dir).items()
            if definition.get("result_type") != "incidental"}


def load_fill_rate_rows(json_dir: str) -> List[Dict[str, Any]]:
    """Collect every fill-rate measurement per scenario (test case).

    Covers all *_fill_rate specs (route fill rates AND fdb_fill_rate). Unlike
    load_actual_specs, this does NOT dedupe by (spec_name, operation): each
    route-scale case emits the same spec_name (ipv4_route_fill_rate ...) with
    operation "", so deduping would collapse all deployment scenarios (mask16 /
    mask24 / mixed ...) into one. Here each file = one scenario, so we keep them
    all. Fill percentage is `value`; attempted and completed entries live in
    typed `details` fields.
    """
    out: List[Dict[str, Any]] = []
    json_path = Path(json_dir)
    if not json_path.exists():
        return out
    for jf in json_path.glob("*.json"):
        if jf.name == "ptf_results.json":
            continue
        try:
            with open(jf, 'r') as f:
                data = json.load(f)
        except Exception:
            continue
        tc = data.get("test_class", "")
        for spec in data.get("spec_results", []):
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


def load_ptf_results(ptf_results_path: Optional[str]) -> Dict[str, str]:
    """Load case-level PTF results (reserved; not rendered by this report)."""
    if not ptf_results_path or not os.path.exists(ptf_results_path):
        return {}
    try:
        with open(ptf_results_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: failed to load ptf results: {e}")
        return {}


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
    for key in sorted(set(expected) | set(actual)):
        registered = definitions.get(key, {})
        measured = actual.get(key)
        if measured and not registered:
            raise ValueError("unregistered measured spec: %s/%s" % key)
        source = registered
        rt = _norm_type(source.get("result_type"))
        if rt == "incidental":
            continue
        spec_name, operation = key
        direction = source.get("direction", "higher_better")
        value = measured.get("value") if measured else None
        threshold = measured.get("threshold") if measured else None
        rows.append(SpecRow(
            spec_name=spec_name, operation=operation, result_type=rt,
            unit=source.get("unit", ""), direction=direction,
            value=value,
            details=measured.get("details", {}) if measured else {},
            result=(_decide_result(value, threshold, direction)
                    if measured else "NOT MEASURED"),
            test_class=measured.get("test_class", "") if measured else ""))

    return rows


def summarize(rows: List[SpecRow], build_id, asic_type) -> ReportSummary:
    s = ReportSummary(build_id=build_id, asic_type=asic_type,
                      timestamp=datetime.now().isoformat(timespec="seconds"))
    for r in rows:
        if r.result == "NOT MEASURED":
            s.not_measured += 1
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
        elif r.result_type == "capability":
            s.cap_total += 1
            if r.result == "PASS":
                s.cap_pass += 1
            elif r.result == "FAIL":
                s.cap_fail += 1
            elif r.result == "MEASURED":
                s.cap_measured += 1
        # 'incidental' specs are not summarized (and not rendered).
    return s


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _fmt_num(v):
    if isinstance(v, (int, float)):
        return f"{v:,.2f}" if isinstance(v, float) else f"{v:,}"
    return "—"


def _result_class(result: str) -> str:
    if result == "PASS":
        return "pass"
    if result == "FAIL":
        return "fail"
    if result == "NOT MEASURED":
        return "notmeasured"
    if result == "MEASURED":
        return "measured"
    return ""


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


def _html_open(report_title, h1_text, summary, nav_html=""):
    h = ["<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">",
         "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">",
         f"<title>{report_title}</title><style>", _CSS]
    h.append("</style></head><body><div class=\"container\">")
    sub = []
    if summary.asic_type:
        sub.append(summary.asic_type.upper())
    if summary.build_id:
        sub.append(f"Build #{summary.build_id}")
    sub_txt = ("<span class=\"sub\">" + "  ·  ".join(sub) + "</span>") if sub else ""
    h.append(f"<h1>{h1_text}{sub_txt}</h1>")
    if nav_html:
        h.append(f"<div class=\"meta\">{nav_html}</div>")
    h.append(f"<div class=\"meta\"><strong>Generated:</strong> {summary.timestamp}</div>")
    return h


def _nm_count(rows, want_cap: bool) -> int:
    return sum(1 for r in rows
               if r.result == "NOT MEASURED"
               and (r.result_type == "capability") == want_cap)


def generate_html_report(summary: ReportSummary, rows: List[SpecRow],
                         actual: Dict[tuple, Dict[str, Any]],
                         route_fill_rows: Optional[List[Dict[str, Any]]] = None,
                         cap_report_name: Optional[str] = None,
                         result_report_name: Optional[str] = None) -> str:
    """Main page: performance / scale / fill-rate / route-flap / counters.

    Capability is reported separately at value granularity by the SAI repo tool
    ptf/ranking_test/report/render_capability.py.
    """
    route_fill_rows = route_fill_rows or []
    nav_links = []
    if result_report_name:
        nav_links.append(f"<a href=\"{result_report_name}\">→ Test Execution report</a>")
    if cap_report_name:
        nav_links.append(f"<a href=\"{cap_report_name}\">→ Basic Function (Capability) report</a>")
    nav = "&nbsp;&nbsp;·&nbsp;&nbsp;".join(nav_links)
    h = _html_open("SAI Spec Test Report", "SAI Spec Test Report",
                   summary, nav)

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
        h.append(_pivot_table("Op Latency (ms)", op_lat, header_unit="ms"))
    if scale:
        h.append(_pivot_table("Scale (capacity)", scale))
    if route_fill_rows:
        h.append(_fill_rate_table(route_fill_rows, actual))

    h.append("</div></body></html>")
    return "\n".join(h)


def _card(title, value, cls=""):
    return (f"<div class=\"summary-card {cls}\"><h3>{title}</h3>"
            f"<div class=\"value\">{value}</div></div>")


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


# Display label for the three-state result, with leading glyph.
_RESULT_TEXT = {
    "PASS": "✓ PASS",
    "FAIL": "✗ FAIL",
    "MEASURED": "▫ MEASURED",
    "NOT MEASURED": "⛔ NOT MEASURED",
}


def _result_text(result: str) -> str:
    return _RESULT_TEXT.get(result, result)


def _metric_label(r) -> str:
    """Row identity = spec_name·operation, the cross-chip join key."""
    if r.operation:
        return (f"<strong>{r.spec_name}</strong>"
                f"<span class=\"op\">·{r.operation}</span>")
    return f"<strong>{r.spec_name}</strong>"


def _num_unit(num_str: str, unit: str) -> str:
    """Self-contained value: bold number + dimmed small unit suffix."""
    if not unit:
        return f"<span class=\"val\">{num_str}</span>"
    return (f"<span class=\"val\">{num_str}</span>"
            f"<span class=\"unit\">{unit}</span>")


def _value_cell(r) -> str:
    """The single key-data column. Self-contained (value + unit)."""
    if r.result == "NOT MEASURED":
        return "<span class=\"na\">n/m</span>"
    a = r.value
    rt = r.result_type
    if rt == "capability":
        if a == 1:
            return "<span class=\"yes\">✓ Supported</span>"
        if a == 0:
            return "<span class=\"no\">✗ Not supported</span>"
        return "<span class=\"na\">—</span>"
    if rt == "fill_rate":
        return (f"<span class=\"val\">{a:.2f}%</span>"
                if isinstance(a, (int, float)) else "<span class=\"na\">—</span>")
    # performance / scale: number + unit
    if isinstance(a, (int, float)):
        return _num_unit(_fmt_num(a), r.unit)
    return "<span class=\"na\">—</span>"


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
    ta = f" title=\"{tip}\"" if tip else ""
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


def _capacity_of(spec_name, actual):
    """Smallest measured scale spec backing this fill-rate spec.

    v4 and v6 available counts are two views of one shared route table, so the
    conservative single value is the basis -- summing them would claim a
    capacity no chip can deliver.

    Returns (scale, contributing specs); scale is None when none was measured.
    """
    scale, used = None, []
    for cap_spec in _CAPACITY_OF.get(spec_name, ()):
        v = (actual.get((cap_spec, "")) or {}).get("value")
        if isinstance(v, (int, float)):
            scale = v if scale is None else min(scale, v)
            used.append(cap_spec)
    return scale, used


def _fill_rate_table(rfrows, actual) -> str:
    """Fill rate dimensioned by deployment scenario (test case).

    Covers route fill rates and fdb_fill_rate alike. One row per case:
    scenario | capacity | installed scale | fill rate (+ attempted in tooltip).
    The fill cell is colored by its own result.
    """
    out = ["<h2>Fill Rate &amp; Scale</h2>",
           "<table><thead><tr>",
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
        cap, cap_src = _capacity_of(r["spec_name"], actual)
        if cap is None:
            cap_cell = "<td><span class=\"na\">—</span></td>"
        else:
            src = ', '.join(cap_src)
            if len(cap_src) > 1:
                src = "min of " + src
            cap_cell = (f"<td title=\"from {src}\">"
                        f"<span class=\"val\">{_fmt_num(cap)}</span></td>")
        # attempted (the fill-rate denominator) is derivable from fill% and
        # installed, so it lives in the tooltip rather than its own column.
        att = (f"attempted {_fmt_num(r['attempted'])}"
               if isinstance(r["attempted"], (int, float)) else "")
        ta = f" title=\"{att}\"" if att else ""
        scenario = r["test_class"] or "—"
        if r.get("order"):
            scenario += f" ({r['order']})"
        out.append(f"<tr{ta}><td><strong>{scenario}</strong></td>")
        out.append(cap_cell)
        out.append(f"<td><span class=\"val\">{inst}</span></td>")
        out.append(f"<td class=\"{colorcls}\"><span class=\"val\">{fill}</span></td></tr>")
    out.append("</tbody></table>")
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
        return " ".join("PG" if w == "pg" else w for w in base.split("_"))

    def _verb(op):
        return {"read": "Read", "clear": "Clear"}.get(op, (op or "read").capitalize())

    ordered = sorted(rows, key=lambda r: (r.spec_name,
                                          0 if r.operation == "read" else 1))
    out = ["<h2>Counter perf</h2><table><thead><tr>"
           "<th>Counter perf</th><th>Time</th></tr></thead><tbody>"]
    for r in ordered:
        observed = r.details.get('observed_count')
        cnt = (f"{int(observed)} "
               if isinstance(observed, (int, float)) and observed else "")
        desc = f"{_verb(r.operation)} {cnt}{_obj(r.spec_name)} counters"
        colorcls = {"PASS": "pass", "FAIL": "fail",
                    "MEASURED": "measured"}.get(r.result, "")
        if r.result == "NOT MEASURED":
            cell = '<td class="fail"><span class="na">n/m</span></td>'
        elif isinstance(r.details.get('duration_seconds'), (int, float)):
            cell = (f'<td class="{colorcls}"><span class="val">'
                    f"{r.details['duration_seconds'] * 1000:.1f} ms</span></td>")
        else:
            cell = '<td><span class="na">—</span></td>'
        out.append(f"<tr><td>{desc}</td>{cell}</tr>")
    out.append("</tbody></table>")
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
        by_spec.setdefault(r.spec_name, {})[r.operation] = r
    ops = sorted({r.operation for r in rows}, key=_op_sort_key)
    single = collapse or (ops == [""])

    hdr = (f"Measured ({header_unit})" if (single and header_unit) else "Measured")
    out = [f"<h2>{title}</h2><table><thead><tr><th>Metric</th>"]
    if single:
        out.append(f"<th>{hdr}</th>")
    else:
        for op in ops:
            label = op if op else "—"
            note = _OP_NOTE.get(op)
            if note:
                label += f"<span class=\"op-note\">({note})</span>"
            if header_unit:
                label += f"<span class=\"unit\">{header_unit}</span>"
            out.append(f"<th>{label}</th>")
    out.append("</tr></thead><tbody>")

    for spec in sorted(by_spec):
        opmap = by_spec[spec]
        all_nm = all(x.result == "NOT MEASURED" for x in opmap.values())
        rowcls = "row-notmeasured" if all_nm else ""
        out.append(f"<tr class=\"{rowcls}\"><td><strong>{spec}</strong></td>")
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
    out.append("</tbody></table>")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Text report (kept minimal, mirrors the three tables)
# ---------------------------------------------------------------------------

def generate_text_report(summary: ReportSummary, rows: List[SpecRow]) -> str:
    L = ["=" * 78, "  SAI Spec Test Report"]
    if summary.asic_type:
        L.append(f"  ASIC: {summary.asic_type}")
    if summary.build_id:
        L.append(f"  Build: {summary.build_id}")
    L.append(f"  Generated: {summary.timestamp}")
    L.append("=" * 78)
    L.append("")

    def _seg(label, npass, nfail, nmeasured, total):
        if total == 0:
            return f"{label} -"
        if npass > 0 or nfail > 0:
            return f"{label} PASS {npass}/{total}"
        if nmeasured > 0:
            return f"{label} MEASURED {nmeasured}/{total}"
        return f"{label} NOT MEASURED 0/{total}"

    L.append(" | ".join([
        _seg("Performance", summary.perf_pass, summary.perf_fail, summary.perf_measured, summary.perf_total),
        _seg("Scale", summary.scale_pass, summary.scale_fail, summary.scale_measured, summary.scale_total),
        _seg("Fill Rate", summary.fill_pass, summary.fill_fail, summary.fill_measured, summary.fill_total),
        _seg("Capability", summary.cap_pass, summary.cap_fail, summary.cap_measured, summary.cap_total),
        f"NOT MEASURED {summary.not_measured}",
    ]))
    L.append("")
    for label, rt in (("Performance", "performance"), ("Scale", "scale"),
                      ("Fill Rate", "fill_rate"), ("Capability", "capability")):
        sub = [r for r in rows if r.result_type == rt]
        if not sub:
            continue
        L.append(f"--- {label} ---")
        for r in sorted(sub, key=lambda x: (x.spec_name, x.operation)):
            mark = {"PASS": "✅", "FAIL": "❌", "NOT MEASURED": "⛔",
                    "MEASURED": "▫"}.get(r.result, "?")
            actual = _fmt_num(r.value) if r.value is not None else "NOT MEASURED"
            L.append(f"  {mark} {r.spec_name} {r.operation}: "
                     f"{actual} {r.unit}")
        L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Generate SAI spec metric report")
    p.add_argument("--json-dir", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--format", choices=["html", "text"], default="html")
    p.add_argument("--build-id", default=None)
    p.add_argument("--asic-type", default=None)
    p.add_argument("--ptf-results", default=None,
                   help="(optional) ptf_results.json; not rendered, reserved.")
    p.add_argument("--result-report", default="result.html",
                   help="file name of the test execution report to link back to "
                        "(default: result.html). Set empty to omit the link.")
    p.add_argument("--cap-report", default="capability.html",
                   help="file name of the value-level capability report to link "
                        "to (default: capability.html). That report is rendered "
                        "by the SAI repo tool ptf/ranking_test/report/"
                        "render_capability.py. "
                        "Set empty to omit the link.")
    args = p.parse_args()

    actual = load_actual_specs(args.json_dir)
    definitions = load_registry_definitions(args.json_dir)
    expected = {key: definition for key, definition in definitions.items()
                if definition.get("result_type") != "incidental"}
    route_fill_rows = load_fill_rate_rows(args.json_dir)
    print(f"Loaded {len(actual)} actual spec results, "
          f"{len(expected)} registered metric cells, "
          f"{len(route_fill_rows)} fill-rate scenarios")

    rows = build_spec_rows(actual, expected, definitions)
    summary = summarize(rows, args.build_id, args.asic_type)

    if args.format == "html":
        report = generate_html_report(summary, rows, actual, route_fill_rows,
                                      cap_report_name=args.cap_report,
                                      result_report_name=args.result_report)
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Spec report generated: {args.output}")
    else:
        report = generate_text_report(summary, rows)
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Report generated: {args.output}")
    print(f"perf {summary.perf_pass}/{summary.perf_total}, "
          f"scale {summary.scale_pass}/{summary.scale_total}, "
          f"cap {summary.cap_pass}/{summary.cap_total}, "
          f"NOT MEASURED {summary.not_measured}")


if __name__ == "__main__":
    main()
