"""
Pytest plugin: SAI-level fidelity scoring for SONiC VS (libsaivs) testbeds.

Opt-in via --sai-fidelity. For each test on a VS DUT, captures sairedis.rec
deltas, classifies SAI ops into confidence tiers, and emits a per-test score.
Never fails or errors a test because of this plugin.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Tuple

import pytest

from . import tier_engine

logger = logging.getLogger(__name__)

# Ops fidelity cares about (notify is dropped inside tier_engine)
FIDELITY_OPS = frozenset(
    ("create", "remove", "set", "get", "stats", "clearstats")
)

# Session-level accumulation for terminal summary / JSON
_results: List[Dict[str, Any]] = []


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
    """Attach the scoring fixture only when --sai-fidelity is set."""
    if not config.getoption("--sai-fidelity", default=False):
        return
    if getattr(config, "_sai_fidelity_table", None) is None:
        return
    for item in items:
        if "_sai_fidelity_score" not in item.fixturenames:
            item.fixturenames.append("_sai_fidelity_score")


def _marker_enabled(item) -> bool:
    """Return False if the test opted out via @pytest.mark.sai_fidelity(enabled=False)."""
    marker = item.get_closest_marker("sai_fidelity")
    if marker is None:
        return True
    if marker.kwargs.get("enabled", True) is False:
        return False
    if marker.args and marker.args[0] is False:
        return False
    return True


def _resolve_vs_duthosts(request) -> List[Any]:
    """Lazily resolve VS DUTs; never raise into the test."""
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


def _snapshot_lines(hosts) -> Dict[Tuple[str, str], int]:
    """Map (hostname, rec_path) -> line count at test start."""
    # Import here so unit tests / non-DASH collection do not need dash package
    from tests.dash.sairedis_utils import get_sairedis_line_count, sairedis_rec_paths

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
                snaps[(hostname, path)] = get_sairedis_line_count(host, rec_path=path)
            except Exception as exc:
                logger.warning(
                    "SAI fidelity: wc -l failed for %s:%s: %s", hostname, path, exc
                )
                snaps[(hostname, path)] = 0
    return snaps


def _parse_delta(hosts, snaps):
    from tests.dash.sairedis_utils import (
        iter_changes,
        parse_sairedis_changes,
    )

    all_changes = []
    host_by_name = {getattr(h, "hostname", str(h)): h for h in hosts}

    for (hostname, path), start_line in snaps.items():
        host = host_by_name.get(hostname)
        if host is None:
            continue
        try:
            changes = parse_sairedis_changes(
                host,
                start_line=start_line,
                rec_path=path,
                include_ops=FIDELITY_OPS,
            )
            all_changes.extend(iter_changes(changes))
        except Exception as exc:
            logger.warning(
                "SAI fidelity: parse failed for %s:%s: %s", hostname, path, exc
            )
    return all_changes


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
    }

    if not _marker_enabled(item):
        record["summary"] = "opted out via sai_fidelity(enabled=False)"
        logger.info("SAI fidelity: %s — %s", item.nodeid, record["summary"])
        _results.append(record)
        yield
        return

    table = getattr(request.config, "_sai_fidelity_table", None)
    if table is None:
        record["summary"] = "tier table unavailable"
        record["error"] = "tier table unavailable"
        _results.append(record)
        yield
        return

    hosts = _resolve_vs_duthosts(request)
    if not hosts:
        record["summary"] = "no VS DUT (score=None)"
        record["error"] = "no VS DUT"
        logger.warning("SAI fidelity: %s — %s", item.nodeid, record["summary"])
        _attach_properties(item, record)
        _results.append(record)
        yield
        return

    snaps = {}
    try:
        snaps = _snapshot_lines(hosts)
    except Exception as exc:
        record["error"] = "snapshot failed: {}".format(exc)
        logger.warning("SAI fidelity: snapshot failed for %s: %s", item.nodeid, exc)

    yield

    try:
        changes = _parse_delta(hosts, snaps)
        counts = tier_engine.count_tiers(changes, table)
        n1, n2, n3 = counts.get(1, 0), counts.get(2, 0), counts.get(3, 0)
        score = tier_engine.calc_score(n1, n2, n3, weights=table.weights)
        summary = tier_engine.format_summary(n1, n2, n3, score)
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
        logger.info("SAI fidelity: %s — %s", item.nodeid, summary)
    except Exception as exc:
        record["error"] = str(exc)
        record["summary"] = "scoring failed (score=None)"
        logger.warning(
            "SAI fidelity: scoring failed for %s: %s", item.nodeid, exc
        )

    _attach_properties(item, record)
    _results.append(record)


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
    except Exception as exc:
        logger.warning("SAI fidelity: failed to attach user_properties: %s", exc)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if call.when != "call":
        return
    # Stamp outcome onto the latest matching record
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
    scored = [r for r in _results if r.get("score") is not None]
    total_calls = sum(r["total"] for r in _results)
    sum_n1 = sum(r["n1"] for r in _results)
    sum_n2 = sum(r["n2"] for r in _results)
    sum_n3 = sum(r["n3"] for r in _results)
    run_score = tier_engine.calc_score(
        sum_n1,
        sum_n2,
        sum_n3,
        weights=getattr(
            getattr(config, "_sai_fidelity_table", None),
            "weights",
            None,
        ),
    )

    for record in _results:
        score_s = (
            "None" if record["score"] is None else "{:.2f}".format(record["score"])
        )
        terminalreporter.write_line(
            "  {}  [{}]  {}  score={}".format(
                record["nodeid"],
                record.get("outcome") or "?",
                record.get("summary") or "",
                score_s,
            )
        )

    terminalreporter.write_line("")
    terminalreporter.write_line(
        "  run totals: {} tests, {} with score, {} SAI calls "
        "(t1={}, t2={}, t3={})  run_score={}".format(
            len(_results),
            len(scored),
            total_calls,
            sum_n1,
            sum_n2,
            sum_n3,
            "None" if run_score is None else "{:.2f}".format(run_score),
        )
    )

    report_path = config.getoption("--sai-fidelity-report")
    try:
        _write_json_report(report_path, _results, run_score, config)
        terminalreporter.write_line("  JSON report: {}".format(report_path))
    except Exception as exc:
        logger.warning("SAI fidelity: failed to write JSON report: %s", exc)
        terminalreporter.write_line(
            "  JSON report write failed: {}".format(exc)
        )


def _write_json_report(path, results, run_score, config):
    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)

    payload = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "tier_file": getattr(config, "_sai_fidelity_tier_path", None),
        "run_score": run_score,
        "tests": [
            {
                "nodeid": r["nodeid"],
                "outcome": r.get("outcome"),
                "total": r["total"],
                "n1": r["n1"],
                "n2": r["n2"],
                "n3": r["n3"],
                "score": r["score"],
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
