"""
Pytest plugin: SAI-level fidelity scoring for SONiC VS (libsaivs) testbeds.

Opt-in via --sai-fidelity. For each test on a VS DUT, captures sairedis.rec
deltas (inode-aware, with .1 stitch on logrotate), classifies SAI ops into
confidence tiers, and emits a per-test score.
Never fails or errors a test because of this plugin.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import pytest

from . import sairedis_window, tier_engine
from .sairedis_window import (
    UNRELIABLE_EMPTY,
    DeltaResult,
    RecSnapshot,
)

logger = logging.getLogger(__name__)

FIDELITY_OPS = frozenset(
    ("create", "remove", "set", "get", "stats", "clearstats")
)

_results: List[Dict[str, Any]] = []
# nodeid -> record while fixture is in flight (for outcome stamping before append)
_pending: Dict[str, Dict[str, Any]] = {}


def pytest_addoption(parser):
    parser.addoption(
        "--sai-fidelity",
        action="store_true",
        default=False,
        help="Enable SAI fidelity scoring from sairedis.rec on VS DUTs "
             "(opt-in; default OFF).",
    )
    parser.addoption(
        "--sai-fidelity-report",
        action="store",
        default="logs/sai_fidelity.json",
        help="JSON report path for SAI fidelity results "
             "(default: logs/sai_fidelity.json).",
    )
    parser.addoption(
        "--sai-fidelity-tier-file",
        action="store",
        default=None,
        help="Override path to tier.yml (default: packaged tier.yml).",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "sai_fidelity(enabled=True): opt out of SAI fidelity scoring with "
        "sai_fidelity(enabled=False) when --sai-fidelity is set.",
    )
    if config.getoption("--sai-fidelity", default=False):
        tier_path = (
            config.getoption("--sai-fidelity-tier-file")
            or tier_engine.default_tier_file()
        )
        try:
            config._sai_fidelity_table = tier_engine.load_tiers(tier_path)
            config._sai_fidelity_tier_path = tier_path
            logger.info("SAI fidelity enabled; tier file: %s", tier_path)
        except Exception as exc:
            logger.warning(
                "SAI fidelity: failed to load tier file %s: %s "
                "(plugin disabled for this run)",
                tier_path,
                exc,
            )
            config._sai_fidelity_table = None


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
    if not config.getoption("--sai-fidelity", default=False):
        return
    if getattr(config, "_sai_fidelity_table", None) is None:
        return
    for item in items:
        if "_sai_fidelity_score" not in item.fixturenames:
            item.fixturenames.append("_sai_fidelity_score")


def _marker_enabled(item) -> bool:
    marker = item.get_closest_marker("sai_fidelity")
    if marker is None:
        return True
    if marker.kwargs.get("enabled", True) is False:
        return False
    if marker.args and marker.args[0] is False:
        return False
    return True


def _resolve_vs_duthosts(request) -> List[Any]:
    hosts = []
    try:
        duthosts = request.getfixturevalue("duthosts")
    except Exception as exc:
        logger.warning("SAI fidelity: cannot resolve duthosts: %s", exc)
        return hosts

    try:
        for duthost in duthosts:
            try:
                asic_type = (duthost.facts or {}).get("asic_type", "")
            except Exception as exc:
                logger.warning(
                    "SAI fidelity: cannot read asic_type on %s: %s",
                    getattr(duthost, "hostname", duthost),
                    exc,
                )
                continue
            if asic_type == "vs":
                hosts.append(duthost)
            else:
                logger.warning(
                    "SAI fidelity: skipping %s (asic_type=%s, need vs)",
                    getattr(duthost, "hostname", duthost),
                    asic_type,
                )
    except Exception as exc:
        logger.warning("SAI fidelity: error enumerating DUTs: %s", exc)
    return hosts


def _snapshot_recs(hosts) -> Dict[Tuple[str, str], RecSnapshot]:
    """Map (hostname, rec_path) -> RecSnapshot."""
    from tests.common.helpers.sairedis_utils import sairedis_rec_paths

    snaps = {}
    for host in hosts:
        hostname = getattr(host, "hostname", str(host))
        try:
            paths = sairedis_rec_paths(host)
        except Exception as exc:
            logger.warning(
                "SAI fidelity: cannot list sairedis paths on %s: %s", hostname, exc
            )
            continue
        for path in paths:
            try:
                snaps[(hostname, path)] = sairedis_window.snapshot_rec(host, path)
            except Exception as exc:
                logger.warning(
                    "SAI fidelity: snapshot failed for %s:%s: %s",
                    hostname,
                    path,
                    exc,
                )
                snaps[(hostname, path)] = RecSnapshot(path=path)
    return snaps


def _collect_changes(hosts, snaps):
    """
    Collect deltas for all snapshots.

    Returns (changes_list, window_meta) where window_meta has overall status
    and reasons. If any path is UNRELIABLE and yields no usable text, overall
    status reflects the worst unreliable reason.
    """
    from tests.common.helpers.sairedis_utils import iter_changes, parse_sairedis_text

    all_changes = []
    statuses = []
    reasons = []
    host_by_name = {getattr(h, "hostname", str(h)): h for h in hosts}

    for (hostname, path), snap in snaps.items():
        host = host_by_name.get(hostname)
        if host is None:
            continue
        try:
            delta = sairedis_window.collect_delta(host, snap)
        except Exception as exc:
            delta = DeltaResult(
                sairedis_window.STATUS_ERROR,
                reason="collect failed: {}".format(exc),
            )
        statuses.append(delta.status)
        if delta.reason:
            reasons.append("{}:{}:{}".format(hostname, path, delta.reason))
        logger.info(
            "SAI fidelity window %s:%s status=%s reason=%s bytes=%s",
            hostname,
            path,
            delta.status,
            delta.reason,
            delta.bytes_read,
        )

        if delta.status in UNRELIABLE_EMPTY and not delta.text.strip():
            continue

        if delta.text.strip():
            try:
                changes = parse_sairedis_text(delta.text, include_ops=FIDELITY_OPS)
                all_changes.extend(iter_changes(changes))
            except Exception as exc:
                logger.warning(
                    "SAI fidelity: parse failed for %s:%s: %s", hostname, path, exc
                )
                statuses.append(sairedis_window.STATUS_ERROR)
                reasons.append("parse:{}".format(exc))

    # Prefer explicit failure statuses over OK when mixed
    priority = [
        sairedis_window.STATUS_ERROR,
        sairedis_window.STATUS_HISTORY_LOST,
        sairedis_window.STATUS_RECORDER_RESET,
        sairedis_window.STATUS_TRUNCATED,
        sairedis_window.STATUS_TOO_LARGE,
        sairedis_window.STATUS_MISSING,
        sairedis_window.STATUS_STITCHED,
        sairedis_window.STATUS_OK,
    ]
    overall = sairedis_window.STATUS_OK
    for cand in priority:
        if cand in statuses:
            overall = cand
            break
    if not statuses:
        overall = sairedis_window.STATUS_MISSING

    meta = {
        "status": overall,
        "statuses": statuses,
        "reasons": reasons,
    }
    return all_changes, meta


@pytest.fixture
def _sai_fidelity_score(request):
    """Snapshot sairedis.rec before the test; score after; never fail the test."""
    item = request.node
    record = {
        "nodeid": item.nodeid,
        "outcome": None,
        "total": 0,
        "n1": 0,
        "n2": 0,
        "n3": 0,
        "score": None,
        "breakdown": [],
        "summary": "skipped",
        "error": None,
        "window_status": None,
    }
    _pending[item.nodeid] = record

    if not _marker_enabled(item):
        record["summary"] = "opted out via sai_fidelity(enabled=False)"
        logger.info("SAI fidelity: %s — %s", item.nodeid, record["summary"])
        _results.append(record)
        _pending.pop(item.nodeid, None)
        yield
        return

    table = getattr(request.config, "_sai_fidelity_table", None)
    if table is None:
        record["summary"] = "tier table unavailable"
        record["error"] = "tier table unavailable"
        _results.append(record)
        _pending.pop(item.nodeid, None)
        yield
        return

    hosts = _resolve_vs_duthosts(request)
    if not hosts:
        record["summary"] = "no VS DUT (score=None)"
        record["error"] = "no VS DUT"
        logger.warning("SAI fidelity: %s — %s", item.nodeid, record["summary"])
        _attach_properties(item, record)
        _results.append(record)
        _pending.pop(item.nodeid, None)
        yield
        return

    snaps = {}
    try:
        snaps = _snapshot_recs(hosts)
    except Exception as exc:
        record["error"] = "snapshot failed: {}".format(exc)
        logger.warning("SAI fidelity: snapshot failed for %s: %s", item.nodeid, exc)

    yield

    # Pull outcome from call report if already stored on item
    for when in ("call", "setup"):
        rep = getattr(item, "rep_" + when, None)
        if rep is not None and record.get("outcome") is None and when == "call":
            record["outcome"] = rep.outcome

    try:
        changes, meta = _collect_changes(hosts, snaps)
        record["window_status"] = meta.get("status")

        unreliable = meta.get("status") in UNRELIABLE_EMPTY
        if unreliable and not changes:
            reason = "; ".join(meta.get("reasons") or []) or meta.get("status")
            record["error"] = reason
            record["summary"] = "window {}: score=None".format(meta.get("status"))
            logger.warning(
                "SAI fidelity: %s — %s (%s)",
                item.nodeid,
                record["summary"],
                reason,
            )
        else:
            counts = tier_engine.count_tiers(changes, table)
            n1, n2, n3 = counts.get(1, 0), counts.get(2, 0), counts.get(3, 0)
            score = tier_engine.calc_score(n1, n2, n3, weights=table.weights)
            summary = tier_engine.format_summary(n1, n2, n3, score)
            if meta.get("status") == sairedis_window.STATUS_STITCHED:
                summary = summary + " [stitched]"
            breakdown = tier_engine.object_type_breakdown(changes, table, top_n=10)
            record.update(
                {
                    "total": n1 + n2 + n3,
                    "n1": n1,
                    "n2": n2,
                    "n3": n3,
                    "score": score,
                    "breakdown": breakdown,
                    "summary": summary,
                }
            )
            if unreliable and changes:
                # Partial recovery with a warning flag
                record["error"] = "partial after {}; {}".format(
                    meta.get("status"),
                    "; ".join(meta.get("reasons") or []),
                )
            logger.info(
                "SAI fidelity: %s — %s (window=%s)",
                item.nodeid,
                summary,
                meta.get("status"),
            )
    except Exception as exc:
        record["error"] = str(exc)
        record["summary"] = "scoring failed (score=None)"
        logger.warning(
            "SAI fidelity: scoring failed for %s: %s", item.nodeid, exc
        )

    _attach_properties(item, record)
    _results.append(record)
    _pending.pop(item.nodeid, None)


def _attach_properties(item, record):
    try:
        item.user_properties.append(("sai_calls", record["total"]))
        item.user_properties.append(("sai_tier1", record["n1"]))
        item.user_properties.append(("sai_tier2", record["n2"]))
        item.user_properties.append(("sai_tier3", record["n3"]))
        score = record["score"]
        item.user_properties.append(
            ("sai_fidelity_score", "" if score is None else score)
        )
        if record.get("window_status"):
            item.user_properties.append(
                ("sai_fidelity_window", record["window_status"])
            )
    except Exception as exc:
        logger.warning("SAI fidelity: failed to attach user_properties: %s", exc)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    setattr(item, "rep_" + rep.when, rep)
    if call.when != "call":
        return
    # Stamp pending record (fixture teardown may not have finished yet)
    pending = _pending.get(item.nodeid)
    if pending is not None and pending.get("outcome") is None:
        pending["outcome"] = rep.outcome
    for record in reversed(_results):
        if record["nodeid"] == item.nodeid and record.get("outcome") is None:
            record["outcome"] = rep.outcome
            break


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    if not config.getoption("--sai-fidelity", default=False):
        return
    if not _results:
        terminalreporter.write_sep("=", "SAI fidelity (no results)")
        return

    terminalreporter.write_sep("=", "SAI fidelity summary")
    n_tests = len(_results)
    scored = [r for r in _results if r.get("score") is not None]
    none_wipe = [
        r
        for r in _results
        if r.get("score") is None
        and r.get("window_status") in UNRELIABLE_EMPTY
    ]
    none_other = [
        r
        for r in _results
        if r.get("score") is None
        and r.get("window_status") not in UNRELIABLE_EMPTY
    ]
    total_calls = sum(r["total"] for r in _results)
    sum_n1 = sum(r["n1"] for r in _results)
    sum_n2 = sum(r["n2"] for r in _results)
    sum_n3 = sum(r["n3"] for r in _results)
    # Mean of per-test scores (includes 1.0 for trusted empty / CP-only tests)
    run_score = (
        sum(r["score"] for r in scored) / float(len(scored)) if scored else None
    )

    def pct(k):
        return (100.0 * k / n_tests) if n_tests else 0.0

    for record in _results:
        score_s = (
            "None" if record["score"] is None else "{:.2f}".format(record["score"])
        )
        win = record.get("window_status") or "-"
        terminalreporter.write_line(
            "  {}  [{}]  {}  window={}  score={}".format(
                record["nodeid"],
                record.get("outcome") or "?",
                record.get("summary") or "",
                win,
                score_s,
            )
        )

    terminalreporter.write_line("")
    terminalreporter.write_line(
        "  scored: {}/{} ({:.0f}%)  |  None(wipe): {}/{} ({:.0f}%)  |  "
        "None(other): {}/{} ({:.0f}%)  |  mean={}".format(
            len(scored),
            n_tests,
            pct(len(scored)),
            len(none_wipe),
            n_tests,
            pct(len(none_wipe)),
            len(none_other),
            n_tests,
            pct(len(none_other)),
            "None" if run_score is None else "{:.2f}".format(run_score),
        )
    )
    terminalreporter.write_line(
        "  run totals: {} tests, {} SAI calls "
        "(t1={}, t2={}, t3={})".format(
            n_tests,
            total_calls,
            sum_n1,
            sum_n2,
            sum_n3,
        )
    )

    report_path = config.getoption("--sai-fidelity-report")
    try:
        _write_json_report(
            report_path,
            _results,
            run_score,
            config,
            stats={
                "n_tests": n_tests,
                "n_scored": len(scored),
                "pct_scored": pct(len(scored)),
                "n_none_wipe": len(none_wipe),
                "pct_none_wipe": pct(len(none_wipe)),
                "n_none_other": len(none_other),
                "pct_none_other": pct(len(none_other)),
                "mean_score": run_score,
            },
        )
        terminalreporter.write_line("  JSON report: {}".format(report_path))
    except Exception as exc:
        logger.warning("SAI fidelity: failed to write JSON report: %s", exc)
        terminalreporter.write_line(
            "  JSON report write failed: {}".format(exc)
        )


def _write_json_report(path, results, run_score, config, stats=None):
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tier_file": getattr(config, "_sai_fidelity_tier_path", None),
        "run_score": run_score,
        "stats": stats or {},
        "tests": [
            {
                "nodeid": r["nodeid"],
                "outcome": r.get("outcome"),
                "total": r["total"],
                "n1": r["n1"],
                "n2": r["n2"],
                "n3": r["n3"],
                "score": r["score"],
                "window_status": r.get("window_status"),
                "breakdown": r.get("breakdown") or [],
                "summary": r.get("summary"),
                "error": r.get("error"),
            }
            for r in results
        ],
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2, sort_keys=False)
        fh.write("\n")
