"""Historical replay for ``presearch_filter.py``.

Pulls the last N days of ``PRBinarySearchResult`` rows from Kusto and asks,
for each one, "what would ``PreSearchFilter`` have decided if it had run
*just before* this search was dispatched?"  Compares the simulated decision
against the search's actual outcome and reports recall + noise reduction.

This is the recommended way to validate any future change to filter
thresholds or filter logic.  Run it before raising the PR.

Usage::

    export ACCESS_TOKEN=$(az account get-access-token \\
        --resource https://api.kusto.windows.net --query accessToken -o tsv)
    cd test_analyzer/pr_binary_search
    python tests/replay_presearch_filter.py --days 30

    # Or replay against the committed 2026-05-26 snapshot:
    python tests/replay_presearch_filter.py \\
        --snapshot tests/replay_kusto_data_2026-05-26.json

The script is read-only — it never writes back to Kusto.
"""
from __future__ import annotations

import argparse
import ast
import json
import logging
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.dirname(HERE)
sys.path.insert(0, PKG)

from presearch_filter import (  # noqa: E402
    STATIC_BLOCKLIST,
    F1_LOOKBACK_DAYS,
    F1_REPEAT_BAD_COMMIT_THRESHOLD,
    F2_PASS_RATE_THRESHOLD,
    F2_MIN_RUNS,
    F3_MAX_UNKNOWN_SEARCHES,
    F3_LOOKBACK_DAYS,
)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def evaluate_at(t_now, entry, prior_idx, pass_idx):
    """Return ``(filter_name, reason, details)`` for the first filter that
    would have skipped this entry, or ``None`` if all default-enabled filters
    pass.  Mirrors the production semantics for F0-F3.  F4 is intentionally
    skipped: it is off in the default enabled set and a full replay would
    need per-entry V2TestCases queries."""
    testcase = entry["TestCase"]
    checker = entry["CheckerType"]
    branch = entry["Branch"]
    file_path = entry["FilePath"]

    if (testcase, checker) in STATIC_BLOCKLIST:
        return ("F0_STATIC_BLOCKLIST", "in static blocklist", {})

    history = [pr for pr in prior_idx.get((testcase, checker, branch), [])
               if pr["UploadTime"] is not None and pr["UploadTime"] < t_now]

    # F1 — within lookback, look at both "recent bad_commit" and "repeated
    # same bad_commit" subcases.
    f1_window = t_now - timedelta(days=F1_LOOKBACK_DAYS)
    in_window = sorted([p for p in history if p["UploadTime"] >= f1_window],
                       key=lambda p: p["UploadTime"], reverse=True)
    if in_window:
        # Repeat-bad-commit subcase
        bc_counts = {}
        for p in in_window:
            if p.get("Outcome") == "bad_commit":
                bc = str(p.get("BadCommit") or "")
                if bc:
                    bc_counts[bc] = bc_counts.get(bc, 0) + 1
        for bc, c in bc_counts.items():
            if c >= F1_REPEAT_BAD_COMMIT_THRESHOLD:
                return ("F1_EXISTING_RESULT",
                        f"repeat bad_commit {bc[:12]} x{c} in "
                        f"{F1_LOOKBACK_DAYS}d",
                        {"subcase": "repeat_bad_commit",
                         "bad_commit": bc, "repeat_count": c})
        # Recent bad_commit subcase
        last = in_window[0]
        if last.get("Outcome") == "bad_commit" and last.get("BadCommit"):
            return ("F1_EXISTING_RESULT",
                    f"last result {str(last['BadCommit'])[:12]} "
                    f"({(t_now - last['UploadTime']).days}d ago)",
                    {"subcase": "recent_bad_commit",
                     "bad_commit": str(last["BadCommit"])})

    # F2 — pass-rate
    pr_data = pass_idx.get((testcase, file_path, branch))
    if pr_data:
        total, passes = pr_data
        if total >= F2_MIN_RUNS:
            rate = passes / total
            if rate >= F2_PASS_RATE_THRESHOLD:
                return ("F2_HIGH_PASS_RATE",
                        f"pass_rate={rate:.0%} on {total} runs", {})

    # F3 — last N completed within F3_LOOKBACK_DAYS all unknown
    f3_window = t_now - timedelta(days=F3_LOOKBACK_DAYS)
    last_n = sorted([p for p in history if p["UploadTime"] >= f3_window],
                    key=lambda p: p["UploadTime"], reverse=True
                    )[:F3_MAX_UNKNOWN_SEARCHES]
    if (len(last_n) >= F3_MAX_UNKNOWN_SEARCHES
            and all(p.get("Outcome") == "unknown" for p in last_n)):
        return ("F3_CIRCUIT_BREAKER",
                f"last {F3_MAX_UNKNOWN_SEARCHES} consecutive unknowns "
                f"in {F3_LOOKBACK_DAYS}d", {})
    return None


def _parse_dt(s):
    if not s:
        return None
    if isinstance(s, datetime):
        return s if s.tzinfo else s.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def _fetch_via_kusto_client(days: int):
    from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
    cluster = os.environ.get("KUSTO_CLUSTER_URL",
                             "https://sonicrepodatadev.kusto.windows.net")
    token = os.environ["ACCESS_TOKEN"]
    kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(
        cluster, token)
    client = KustoClient(kcsb)
    db = os.environ.get("KUSTO_DATABASE", "SonicTestData")

    def _q(query):
        resp = client.execute(db, query)
        t = resp.primary_results[0]
        cols = [c.column_name for c in t.columns]
        return [dict(zip(cols, row)) for row in t.rows]

    history = _q(f"""
        PRBinarySearchResult
        | where UploadTime > ago({days}d) and SearchCompleted == true
        | project SearchRunId, UploadTime, Branch, TestCase, CheckerType,
                  FilePath, RootCauseType, BadCommit
        | order by UploadTime asc
    """)
    prior = _q(f"""
        PRBinarySearchResult
        | where UploadTime > ago({days * 2}d) and SearchCompleted == true
        | summarize PriorRows = make_list(pack('UploadTime', UploadTime,
            'Outcome', RootCauseType, 'BadCommit', BadCommit,
            'SearchRunId', SearchRunId)) by TestCase, CheckerType, Branch
    """)
    passrate = _q(f"""
        let cands = PRBinarySearchResult
            | where UploadTime > ago({days}d)
            | distinct TestCase, FilePath, Branch;
        V2TestCases
        | where UploadTime > ago({days + 15}d) and Result != 'skipped'
        | join kind=inner (cands) on TestCase, FilePath
        | join kind=inner (TestPlans | project TestPlanId, TestBranch) on TestPlanId
        | where Branch == TestBranch
        | summarize TotalRuns = count(),
                    Passes = countif(Result in ('passed', 'success'))
          by TestCase, FilePath, Branch
    """)
    return {"history": history, "prior": prior, "passrate": passrate}


def _load_snapshot(path: str):
    """Load a JSON snapshot.  Accepts either parsed-rows form or the
    MCP-driver raw_text/markdown-table form."""
    raw = json.load(open(path))

    def _parse_md(text):
        lines = [ln for ln in text.splitlines() if ln.strip()]
        start = None
        for i, ln in enumerate(lines):
            if "|" in ln and not ln.startswith("**"):
                start = i
                break
        if start is None:
            return []
        header = [c.strip() for c in lines[start].split("|")]
        rows = []
        for ln in lines[start + 2:]:
            if "|" not in ln:
                continue
            parts = [c.strip() for c in ln.split("|")]
            if len(parts) == len(header):
                rows.append(dict(zip(header, parts)))
        return rows

    def _norm(blob):
        if isinstance(blob, list):
            return blob
        if isinstance(blob, dict) and "raw_text" in blob:
            return _parse_md(blob["raw_text"])
        return []

    return {k: _norm(raw.get(k, [])) for k in ("history", "prior", "passrate")}


def _build_indexes(data):
    prior_idx = defaultdict(list)
    for row in data["prior"]:
        key = (row["TestCase"], row["CheckerType"], row["Branch"])
        blob = row["PriorRows"]
        if isinstance(blob, str):
            try:
                blob = ast.literal_eval(blob)
            except Exception:
                blob = []
        for pr in blob or []:
            pr["UploadTime"] = _parse_dt(pr.get("UploadTime"))
            prior_idx[key].append(pr)
        prior_idx[key].sort(
            key=lambda r: r["UploadTime"] or datetime.min.replace(tzinfo=timezone.utc))

    pass_idx = {}
    for row in data["passrate"]:
        try:
            total = int(row["TotalRuns"])
            passes = int(row["Passes"])
        except Exception:
            continue
        pass_idx[(row["TestCase"], row["FilePath"], row["Branch"])] = (total, passes)
    return prior_idx, pass_idx


def run(data):
    history = data["history"]
    prior_idx, pass_idx = _build_indexes(data)
    outcome_counts = Counter(r.get("RootCauseType", "<none>") for r in history)
    skip = defaultdict(Counter)
    passed = Counter()
    examples = defaultdict(list)
    # New metric: count rediscoveries of an already-known bad_commit that the
    # filter would have prevented.  These are "noise we couldn't see in the
    # unknown count" — bisecting again costs the same as bisecting an unknown,
    # but the outcome looks like a "find" so it's invisible in recall/NR.
    repeat_bad_avoided = 0
    for row in history:
        t_now = _parse_dt(row.get("UploadTime"))
        if t_now is None:
            continue
        outcome = row.get("RootCauseType") or "unknown"
        decision = evaluate_at(t_now, row, prior_idx, pass_idx)
        if decision is None:
            passed[outcome] += 1
            continue
        name, reason, details = decision
        skip[outcome][name] += 1
        # Count "rediscovery prevented": the row IS a bad_commit, was skipped
        # by the repeat-bad-commit subcase, AND the BadCommit on the row
        # matches the one we'd already seen.
        if (outcome == "bad_commit"
                and name == "F1_EXISTING_RESULT"
                and details.get("subcase") == "repeat_bad_commit"
                and str(row.get("BadCommit") or "") == details.get("bad_commit")):
            repeat_bad_avoided += 1
        if len(examples[name]) < 4:
            examples[name].append({
                "test": row["TestCase"], "checker": row["CheckerType"],
                "outcome": outcome, "reason": reason,
                "upload": str(row.get("UploadTime")),
                "details": details,
            })
    return {
        "total": len(history),
        "outcomes": dict(outcome_counts),
        "skip": {k: dict(v) for k, v in skip.items()},
        "passed": dict(passed),
        "examples": dict(examples),
        "repeat_bad_commit_avoided": repeat_bad_avoided,
    }


def report(result, fp=sys.stdout):
    total = result["total"]
    bad = result["outcomes"].get("bad_commit", 0)
    unk = result["outcomes"].get("unknown", 0)
    bad_skipped = sum(result["skip"].get("bad_commit", {}).values())
    unk_skipped = sum(result["skip"].get("unknown", {}).values())
    # Effective recall = real misses / new (non-rediscovery) findings.
    # A skipped bad_commit that was a *rediscovery* of an already-known bad
    # commit is NOT a recall miss — the answer was already in Kusto.
    repeat_avoided = result.get("repeat_bad_commit_avoided", 0)
    new_finds = bad - repeat_avoided
    real_misses = bad_skipped - repeat_avoided
    naive_recall = (bad - bad_skipped) / bad if bad else 1.0
    eff_recall = (new_finds - real_misses) / new_finds if new_finds else 1.0
    nr = unk_skipped / unk if unk else 0.0
    print(f"=== Pre-search filter replay ({total} searches) ===", file=fp)
    print(f"True positives (bad_commit): {bad}", file=fp)
    print(f"  kept (naive recall):       {bad - bad_skipped}/{bad} = {naive_recall:.1%}", file=fp)
    print(f"  repeat bad_commit avoided: {repeat_avoided} (re-findings prevented)", file=fp)
    print(f"  effective recall*:         {new_finds - real_misses}/{new_finds} = {eff_recall:.1%}", file=fp)
    print("   * excludes already-known bad_commits from the denominator", file=fp)
    print(f"Noise (unknown):             {unk}", file=fp)
    print(f"  skipped (noise reduction): {unk_skipped}/{unk} = {nr:.1%}", file=fp)
    for outcome, by_reason in result["skip"].items():
        print(f"  by-filter ({outcome}): {by_reason}", file=fp)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--snapshot", default="",
                        help="Path to a pre-fetched JSON snapshot.  If empty, "
                             "the script queries Kusto live "
                             "(requires ACCESS_TOKEN env var).")
    parser.add_argument("--json-out", default="",
                        help="Write result counts to this JSON file.")
    args = parser.parse_args()
    if args.snapshot:
        data = _load_snapshot(args.snapshot)
        logger.info("Loaded snapshot from %s", args.snapshot)
    else:
        data = _fetch_via_kusto_client(args.days)
        logger.info("Fetched %d-day history from Kusto", args.days)
    result = run(data)
    report(result)
    if args.json_out:
        with open(args.json_out, "w") as fp:
            json.dump(result, fp, default=str, indent=2)


if __name__ == "__main__":
    main()
