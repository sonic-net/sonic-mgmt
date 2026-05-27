"""
Pre-search filter for binary search dispatcher.

Runs cheap Kusto-only checks *before* a per-failure pipeline 3305 is queued so
that flaky, pre-existing, or already-resolved failures are filtered out without
spending pipeline minutes.

Filters (ordered cheapest → most expensive):
    F0 — Static blocklist     (in-memory, < 1 ms)
    F1 — Existing result      (1 Kusto query, < 1 s)
    F2 — Historical pass-rate (1 Kusto query, < 1 s)
    F3 — Circuit breaker      (1 Kusto query, < 1 s)
    F4 — Pre-existing failure (1 Kusto query, < 1 s) — opt-in, see below

The dispatcher (``trigger_binary_searches.py``) calls
``PreSearchFilter.evaluate(entry)`` for each parsed failure-info entry returned
by ``parse_failure_info_records``.  Entries are dicts with keys:

    repo, branch, checker, file_path, module_path, testcase,
    failure_join_key, trigger_type, commits, ...

The filter returns a ``FilterDecision`` whose ``passed`` attribute determines
whether the dispatcher should queue a pipeline 3305 run.

Default-enabled filter set is ``{"F0","F1","F2","F3"}``.  **F4 is opt-in**
until the replay tool can validate it on a historical dataset: it requires
per-entry V2TestCases queries which the current 30-day replay snapshot does
not contain, so we do not have evidence it's safe to enable by default.
Pass ``enabled_filters={"F0","F1","F2","F3","F4"}`` to opt in.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from presearch_filter_config import STATIC_BLOCKLIST

logger = logging.getLogger(__name__)

__all__ = [
    "PreSearchFilter",
    "FilterDecision",
    "STATIC_BLOCKLIST",
    "DEFAULT_ENABLED_FILTERS",
    "F1_LOOKBACK_DAYS",
    "F1_REPEAT_BAD_COMMIT_THRESHOLD",
    "F2_LOOKBACK_DAYS",
    "F2_PASS_RATE_THRESHOLD",
    "F2_MIN_RUNS",
    "F3_MAX_UNKNOWN_SEARCHES",
    "F3_LOOKBACK_DAYS",
    "F4_PREEXISTING_DAYS",
    "F4_FAIL_RATE_THRESHOLD",
    "F4_MIN_RUNS",
]

# ---------------------------------------------------------------------------
# Tunables — STATIC_BLOCKLIST lives in presearch_filter_config.py.
# ---------------------------------------------------------------------------

# F1 — Existing result lookback.  Skip when *either* of the following holds:
#   (a) the most recent prior result inside F1_LOOKBACK_DAYS was a bad_commit
#       with an intervening run-of-failures-of-same-test, OR
#   (b) the *same* BadCommit has been identified >= F1_REPEAT_BAD_COMMIT_THRESHOLD
#       times inside F1_LOOKBACK_DAYS (we already know the answer, no point
#       bisecting to the same commit again).
# 30d is intentionally longer than F3_LOOKBACK_DAYS — repeat findings of the
# same bad commit often happen when a fix is reverted or a feature flag flips
# back; the typical inter-failure gap is 10-21 days, so 7d (the original
# value) would miss most of them.
F1_LOOKBACK_DAYS = 30
F1_REPEAT_BAD_COMMIT_THRESHOLD = 2

# F2 — Historical pass-rate gate.  Tuned 90 % → 98 % and min runs 10 → 200
# after the replay showed a 95-%-pass test (test_syslog_rate_limit) sometimes
# carries real regressions.  98 % on 200+ runs over 14d is a strict
# definition of "noisy / probably flaky" that has zero false-skips on the
# 30-day evaluation set.
F2_LOOKBACK_DAYS = 14
F2_PASS_RATE_THRESHOLD = 0.98
F2_MIN_RUNS = 200

# F3 — Circuit breaker on repeated unknowns.  We look at the most recent N
# *completed* searches for the (testcase, checker, branch) triple over a
# generous 60-day window — long enough that low-traffic keys reach N at all,
# and short enough that ancient results don't keep an obviously fixed test
# blocked.  Counter resets the moment any non-unknown result is seen — we
# only count *consecutive* unknowns since the last successful identification.
#
# N=7 / lookback=60d was chosen from the 2026-05-26 replay:
#
#     N | naive recall | noise reduction | F3 fires
#     --+--------------+-----------------+-----------
#     5 |        62.5% |           37.2% | 4 unk + 2 bad
#     7 |        75.0% |           33.3% | 4 unk + 1 bad
#    10 |        87.5% |           32.1% | 1 unk + 0 bad
#
# N=10 keeps the highest recall but makes F3 essentially decorative.
# N=5 (the reviewer's "e.g.") is too aggressive — it false-skips real
# regressions on `test_critical_process_monitoring`.  N=7 is the compromise:
# F3 contributes meaningful noise reduction while only false-skipping one
# bad_commit (a test that is borderline pathological and a candidate for
# the F0 blocklist or for F4 once F4 is validated).
F3_MAX_UNKNOWN_SEARCHES = 7
F3_LOOKBACK_DAYS = 60

# F4 — Pre-existing failure: if the test has been failing for many days before
# the current failure window, it's not a new regression and binary search will
# not converge.  Off by default — see module docstring.
F4_PREEXISTING_DAYS = 7
F4_FAIL_RATE_THRESHOLD = 0.80
F4_MIN_RUNS = 3

DEFAULT_ENABLED_FILTERS = frozenset({"F0", "F1", "F2", "F3"})


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FilterDecision:
    """Outcome of running the filter chain for one failure entry."""

    passed: bool
    skipped_by: Optional[str] = None  # e.g. "F1_EXISTING_RESULT"
    reason: str = ""
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _esc(s) -> str:
    """Escape a string for safe interpolation into a KQL string literal.

    KQL string literals escape a single quote by **doubling** it (``''``),
    not by using backslashes — using ``\\'`` produces invalid KQL and
    defeats injection protection.  Backslashes themselves are still
    doubled defensively since they appear in paths and identifiers.
    """
    if s is None:
        return ""
    return str(s).replace("\\", "\\\\").replace("'", "''")


def _query_kusto(kusto_client, database: str, query: str) -> list[dict]:
    """Execute a read-only KQL query and return rows as dicts.

    Any exception is swallowed and returns ``[]`` — a filter that fails open
    is much safer than one that blocks legitimate regression searches.
    """
    try:
        response = kusto_client.execute(database, query)
        table = response.primary_results[0]
        cols = [c.column_name for c in table.columns]
        return [dict(zip(cols, row)) for row in table.rows]
    except Exception as exc:
        logger.warning("pre-search filter Kusto query failed (%s); passing entry", exc)
        return []


# ---------------------------------------------------------------------------
# Individual filters
# ---------------------------------------------------------------------------

def _filter_0_static_blocklist(entry: dict) -> FilterDecision:
    key = (entry.get("testcase", ""), entry.get("checker", ""))
    if key in STATIC_BLOCKLIST:
        return FilterDecision(
            passed=False,
            skipped_by="F0_STATIC_BLOCKLIST",
            reason=(f"Test {key[0]} on {key[1]} is in the static "
                    f"blocklist (known chronically flaky)."),
        )
    return FilterDecision(passed=True)


def _filter_1_existing_result(kusto_client, database: str, entry: dict) -> FilterDecision:
    """Skip if we have an actionable prior result for the same
    ``(testcase, checker, branch)`` key inside ``F1_LOOKBACK_DAYS``.

    Two cases trigger a skip:

    1. **Most recent prior result is a bad_commit.**  The regression has
       already been root-caused; queueing another search will just rediscover
       the same commit.  Any *non*-bad_commit (unknown / not_reproducible)
       between the bad_commit and now overrides this and lets the entry
       through — that strongly suggests the regression was reverted and the
       current failure is a new one.
    2. **The same BadCommit has been identified >=2 times in the window.**
       This is the "fix wasn't merged or bad commit was re-introduced"
       pattern.  We already know the answer; no need to bisect to it again.
    """
    query = f"""
    PRBinarySearchResult
    | where UploadTime > ago({F1_LOOKBACK_DAYS}d)
    | where TestCase == '{_esc(entry.get("testcase", ""))}'
    | where Branch == '{_esc(entry.get("branch", ""))}'
    | where CheckerType == '{_esc(entry.get("checker", ""))}'
    | where SearchCompleted == true
    | project RootCauseType, BadCommit, UploadTime, SearchRunId
    | order by UploadTime desc
    """
    rows = _query_kusto(kusto_client, database, query)
    if not rows:
        return FilterDecision(passed=True)

    # Case 2: same BadCommit seen multiple times — skip even if most recent
    # was unknown.  The counter only considers non-empty bad_commit findings.
    bad_commit_counts: dict[str, int] = {}
    for r in rows:
        if r.get("RootCauseType") == "bad_commit":
            bc = str(r.get("BadCommit") or "")
            if bc:
                bad_commit_counts[bc] = bad_commit_counts.get(bc, 0) + 1
            else:
                # Data-quality signal: bisection claimed bad_commit but did
                # not record which commit.  Surface it so the team can fix
                # the upstream uploader.
                logger.warning(
                    "PreSearchFilter F1: PRBinarySearchResult row has "
                    "RootCauseType=bad_commit but empty BadCommit "
                    "(SearchRunId=%s)", r.get("SearchRunId"))
    for bc, count in bad_commit_counts.items():
        if count >= F1_REPEAT_BAD_COMMIT_THRESHOLD:
            return FilterDecision(
                passed=False,
                skipped_by="F1_EXISTING_RESULT",
                reason=(f"Same bad_commit {bc[:12]} identified {count} "
                        f"times in last {F1_LOOKBACK_DAYS}d — fix likely "
                        f"not yet merged or commit was re-introduced."),
                details={"bad_commit": bc, "repeat_count": count,
                         "subcase": "repeat_bad_commit"},
            )

    # Case 1: most recent prior result is bad_commit.
    last = rows[0]
    if last.get("RootCauseType") != "bad_commit":
        return FilterDecision(passed=True)
    bad_commit = str(last.get("BadCommit") or "")
    if not bad_commit:
        # Same data-quality signal as above; already logged.  Fail open.
        return FilterDecision(passed=True)
    return FilterDecision(
        passed=False,
        skipped_by="F1_EXISTING_RESULT",
        reason=(f"Most recent prior result was bad_commit {bad_commit[:12]} "
                f"(SearchRunId {str(last.get('SearchRunId', ''))[:8]}); "
                f"no intervening failures suggest the regression is still "
                f"the same one."),
        details={"bad_commit": bad_commit, "subcase": "recent_bad_commit"},
    )


def _filter_2_historical_pass_rate(kusto_client, database: str, entry: dict) -> FilterDecision:
    """Skip if the test has been passing >=98 % of the time recently — almost
    certainly a flaky failure rather than a real regression."""
    testcase = entry.get("testcase", "")
    file_path = entry.get("file_path", "")
    branch = entry.get("branch", "")
    if not testcase or not file_path:
        return FilterDecision(passed=True)

    query = f"""
    V2TestCases
    | where UploadTime > ago({F2_LOOKBACK_DAYS}d)
    | where TestCase == '{_esc(testcase)}'
    | where FilePath == '{_esc(file_path)}'
    | where Result != "skipped"
    | join kind=inner (
        TestPlans
        | where TestBranch == '{_esc(branch)}'
    ) on TestPlanId
    | summarize
        TotalRuns = count(),
        Passes = countif(Result in ("passed", "success"))
    """
    rows = _query_kusto(kusto_client, database, query)
    if not rows:
        return FilterDecision(passed=True)

    total = int(rows[0].get("TotalRuns") or 0)
    passes = int(rows[0].get("Passes") or 0)
    if total < F2_MIN_RUNS:
        return FilterDecision(passed=True)

    pass_rate = passes / total
    if pass_rate < F2_PASS_RATE_THRESHOLD:
        return FilterDecision(passed=True)

    return FilterDecision(
        passed=False,
        skipped_by="F2_HIGH_PASS_RATE",
        reason=(f"Test passes {pass_rate:.0%} of the time over the last "
                f"{F2_LOOKBACK_DAYS} days ({passes}/{total} runs). "
                f"Likely flaky — binary search will not converge."),
        details={"pass_rate": round(pass_rate, 3),
                 "total_runs": total, "passes": passes},
    )


def _filter_3_circuit_breaker(kusto_client, database: str, entry: dict) -> FilterDecision:
    """Skip if the most recent ``F3_MAX_UNKNOWN_SEARCHES`` completed search
    outcomes for this exact ``(testcase, branch, checker)`` triple — within
    ``F3_LOOKBACK_DAYS`` — were *all* ``unknown``.  Any non-unknown result
    resets the gate.

    The lookback is intentionally wide (60d) because real per-key search
    rates are low (~2 / 14d); a narrow window made this filter unreachable
    in practice.
    """
    query = f"""
    PRBinarySearchResult
    | where UploadTime > ago({F3_LOOKBACK_DAYS}d)
    | where TestCase == '{_esc(entry.get("testcase", ""))}'
    | where Branch == '{_esc(entry.get("branch", ""))}'
    | where CheckerType == '{_esc(entry.get("checker", ""))}'
    | where SearchCompleted == true
    | top {F3_MAX_UNKNOWN_SEARCHES} by UploadTime desc
    | project RootCauseType
    """
    rows = _query_kusto(kusto_client, database, query)
    if len(rows) < F3_MAX_UNKNOWN_SEARCHES:
        return FilterDecision(passed=True)

    if all(r.get("RootCauseType") == "unknown" for r in rows):
        return FilterDecision(
            passed=False,
            skipped_by="F3_CIRCUIT_BREAKER",
            reason=(f"Circuit breaker: last {F3_MAX_UNKNOWN_SEARCHES} "
                    f"consecutive completed searches in the past "
                    f"{F3_LOOKBACK_DAYS} days all ended as 'unknown'. "
                    f"Pausing further searches on this test+checker until "
                    f"a non-unknown outcome breaks the streak."),
            details={"consecutive_unknowns": len(rows)},
        )
    return FilterDecision(passed=True)


def _filter_4_preexisting_failure(kusto_client, database: str, entry: dict) -> FilterDecision:
    """Skip if the test has been failing for many days **before** the current
    failure window — it's not a new regression.

    ``span_days`` is computed from the *earliest failing* run rather than
    the earliest run overall: a test that has been clean for 28 days and
    started failing 2 days ago must not be skipped, even though the
    earliest *run* in the 30-day window is 28 days old.
    """
    testcase = entry.get("testcase", "")
    file_path = entry.get("file_path", "")
    branch = entry.get("branch", "")
    if not testcase or not file_path:
        return FilterDecision(passed=True)

    query = f"""
    V2TestCases
    | where UploadTime > ago(30d)
    | where TestCase == '{_esc(testcase)}'
    | where FilePath == '{_esc(file_path)}'
    | where Result != "skipped"
    | join kind=inner (
        TestPlans
        | where TestBranch == '{_esc(branch)}'
    ) on TestPlanId
    | summarize
        TotalRuns = count(),
        Failures = countif(Result !in ("passed", "success")),
        OldestFail = minif(StartTime, Result !in ("passed", "success")),
        NewestFail = maxif(StartTime, Result !in ("passed", "success"))
    """
    rows = _query_kusto(kusto_client, database, query)
    if not rows:
        return FilterDecision(passed=True)

    total = int(rows[0].get("TotalRuns") or 0)
    failures = int(rows[0].get("Failures") or 0)
    if total < F4_MIN_RUNS:
        return FilterDecision(passed=True)

    fail_rate = failures / total
    if fail_rate < F4_FAIL_RATE_THRESHOLD:
        return FilterDecision(passed=True)

    oldest_fail = rows[0].get("OldestFail")
    newest_fail = rows[0].get("NewestFail")
    span_days = 0.0
    try:
        if oldest_fail and newest_fail:
            span_days = (newest_fail - oldest_fail).total_seconds() / 86400.0
    except Exception:
        span_days = 0.0

    if span_days < F4_PREEXISTING_DAYS:
        return FilterDecision(passed=True)

    return FilterDecision(
        passed=False,
        skipped_by="F4_PREEXISTING_FAILURE",
        reason=(f"Test has been failing for {span_days:.0f} days at "
                f"{fail_rate:.0%} fail rate ({failures}/{total} runs). "
                f"Pre-existing failure — not a new regression."),
        details={"fail_rate": round(fail_rate, 3),
                 "span_days": round(span_days, 1),
                 "failures": failures, "total_runs": total},
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class PreSearchFilter:
    """Chain of cheap pre-dispatch checks.

    Usage::

        filt = PreSearchFilter(kusto_client, database="SonicTestData")
        decision = filt.evaluate(entry)
        if decision.passed:
            queue_pipeline_3305(entry)
        else:
            log_skip(entry, decision)

    F4 is **off by default**: pass ``enabled_filters={"F0","F1","F2","F3","F4"}``
    to opt in once it has been validated in the replay tool.
    """

    def __init__(self, kusto_client, database: str = "SonicTestData",
                 enabled_filters: Optional[set[str]] = None):
        self.client = kusto_client
        self.database = database
        self.enabled = (set(enabled_filters)
                        if enabled_filters is not None
                        else set(DEFAULT_ENABLED_FILTERS))

    def evaluate(self, entry: dict) -> FilterDecision:
        """Run the filter chain on a single parsed failure-info entry.
        Short-circuits at the first non-passing filter."""

        steps = [
            ("F0", lambda: _filter_0_static_blocklist(entry)),
            ("F1", lambda: _filter_1_existing_result(self.client, self.database, entry)),
            ("F2", lambda: _filter_2_historical_pass_rate(self.client, self.database, entry)),
            ("F3", lambda: _filter_3_circuit_breaker(self.client, self.database, entry)),
            ("F4", lambda: _filter_4_preexisting_failure(self.client, self.database, entry)),
        ]
        for name, fn in steps:
            if name not in self.enabled:
                continue
            decision = fn()
            if not decision.passed:
                return decision
        return FilterDecision(passed=True)

    def evaluate_many(self, entries: list[dict]) -> tuple[list[dict], list[tuple[dict, FilterDecision]]]:
        """Convenience: split a list of entries into (passing, skipped) pairs.
        ``skipped`` is a list of (entry, decision) so the caller can log and
        upload to Kusto in bulk.

        Skip events are logged at ``WARNING`` (not INFO) so they remain
        visible at default pipeline log verbosity — they represent a
        decision *not* to run a binary search and need to be auditable.
        """
        passing: list[dict] = []
        skipped: list[tuple[dict, FilterDecision]] = []
        skip_counts: dict[str, int] = {}
        for entry in entries:
            decision = self.evaluate(entry)
            if decision.passed:
                passing.append(entry)
            else:
                skipped.append((entry, decision))
                skip_key = decision.skipped_by or "UNKNOWN"
                skip_counts[skip_key] = skip_counts.get(skip_key, 0) + 1
                logger.warning(
                    "PreSearchFilter SKIP key=%s test=%s checker=%s reason=%s details=%s",
                    entry.get("failure_join_key", ""),
                    entry.get("testcase", ""),
                    entry.get("checker", ""),
                    decision.skipped_by,
                    decision.details,
                )
        logger.info(
            "Pre-search filter: %d/%d entries passed (skipped by: %s)",
            len(passing), len(entries), skip_counts or "{}",
        )
        return passing, skipped
