"""Unit tests for presearch_filter.py.

Run with::

    cd test_analyzer/pr_binary_search
    pytest tests/test_presearch_filter.py -v
"""
from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from presearch_filter import (  # noqa: E402
    PreSearchFilter,
    STATIC_BLOCKLIST,
    DEFAULT_ENABLED_FILTERS,
    F1_REPEAT_BAD_COMMIT_THRESHOLD,
    F2_MIN_RUNS,
    F3_MAX_UNKNOWN_SEARCHES,
    F4_MIN_RUNS,
    F4_PREEXISTING_DAYS,
    _filter_0_static_blocklist,
    _filter_1_existing_result,
    _filter_2_historical_pass_rate,
    _filter_3_circuit_breaker,
    _filter_4_preexisting_failure,
    _esc,
)


def now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Helpers — fake Kusto client
# ---------------------------------------------------------------------------

def make_kusto_client(rows_by_substring):
    """Return a KustoClient mock whose ``execute(db, query)`` returns rows
    matching the first key in ``rows_by_substring`` that appears in the query.
    """
    client = MagicMock()

    def execute(db, query):
        chosen = []
        for needle, rows in rows_by_substring.items():
            if needle in query:
                chosen = rows
                break
        cols = sorted({k for r in chosen for k in r}) if chosen else []
        table = MagicMock()
        table.columns = [MagicMock(column_name=c) for c in cols]
        table.rows = [[r.get(c) for c in cols] for r in chosen]
        resp = MagicMock()
        resp.primary_results = [table]
        return resp

    client.execute.side_effect = execute
    return client


def base_entry(**overrides):
    e = {
        "repo": "sonic-net/sonic-mgmt",
        "branch": "master",
        "checker": "t1_checker",
        "file_path": "tests/example/test_example.py",
        "module_path": "tests.example.test_example",
        "testcase": "test_unique_thing",
        "failure_join_key": "abc123",
        "trigger_type": "nightly",
        "commits": ["a", "b", "c"],
    }
    e.update(overrides)
    return e


# ---------------------------------------------------------------------------
# _esc
# ---------------------------------------------------------------------------

def test_esc_handles_single_quotes_and_backslashes():
    # KQL string literals escape single quotes by *doubling* them, not via
    # backslash — see https://learn.microsoft.com/azure/data-explorer/kusto/query/scalar-data-types/string
    assert _esc("it's") == "it''s"
    assert _esc("a\\b") == "a\\\\b"
    assert _esc(None) == ""
    assert _esc(123) == "123"


# ---------------------------------------------------------------------------
# F0 static blocklist
# ---------------------------------------------------------------------------

def test_f0_skips_blocked_pair():
    if not STATIC_BLOCKLIST:
        pytest.skip("STATIC_BLOCKLIST is empty in this build")
    tc, checker = next(iter(STATIC_BLOCKLIST))
    entry = base_entry(testcase=tc, checker=checker)
    decision = _filter_0_static_blocklist(entry)
    assert decision.passed is False
    assert decision.skipped_by == "F0_STATIC_BLOCKLIST"


def test_f0_passes_unrelated_test():
    entry = base_entry(testcase="test_brand_new_thing", checker="t1_checker")
    decision = _filter_0_static_blocklist(entry)
    assert decision.passed is True


# ---------------------------------------------------------------------------
# F1 existing result
# ---------------------------------------------------------------------------

def test_f1_skips_when_most_recent_prior_is_bad_commit():
    client = make_kusto_client({
        "PRBinarySearchResult": [{
            "RootCauseType": "bad_commit",
            "BadCommit": "deadbeef" * 5,
            "UploadTime": now(),
            "SearchRunId": "run-1",
        }],
    })
    decision = _filter_1_existing_result(client, "SonicTestData", base_entry())
    assert decision.passed is False
    assert decision.skipped_by == "F1_EXISTING_RESULT"
    assert decision.details["subcase"] == "recent_bad_commit"
    assert "deadbeef" in decision.details["bad_commit"]


def test_f1_passes_when_most_recent_prior_is_unknown_and_no_repeat():
    client = make_kusto_client({
        "PRBinarySearchResult": [
            {"RootCauseType": "unknown", "BadCommit": "",
             "UploadTime": now(), "SearchRunId": "run-2"},
            {"RootCauseType": "bad_commit", "BadCommit": "oldcommit01",
             "UploadTime": now() - timedelta(days=10), "SearchRunId": "run-1"},
        ],
    })
    decision = _filter_1_existing_result(client, "SonicTestData", base_entry())
    assert decision.passed is True


def test_f1_skips_when_same_bad_commit_seen_multiple_times():
    """Repeat-bad-commit rule: same BadCommit identified >=2 times in the
    window -> fix probably not merged yet; no need to re-bisect."""
    bc = "abc123def456"
    rows = [
        {"RootCauseType": "unknown", "BadCommit": "",
         "UploadTime": now() - timedelta(days=1), "SearchRunId": "r-recent"},
        {"RootCauseType": "bad_commit", "BadCommit": bc,
         "UploadTime": now() - timedelta(days=8), "SearchRunId": "r-2"},
        {"RootCauseType": "bad_commit", "BadCommit": bc,
         "UploadTime": now() - timedelta(days=20), "SearchRunId": "r-1"},
    ]
    client = make_kusto_client({"PRBinarySearchResult": rows})
    decision = _filter_1_existing_result(client, "SonicTestData", base_entry())
    assert decision.passed is False
    assert decision.skipped_by == "F1_EXISTING_RESULT"
    assert decision.details["subcase"] == "repeat_bad_commit"
    assert decision.details["repeat_count"] >= F1_REPEAT_BAD_COMMIT_THRESHOLD
    assert decision.details["bad_commit"] == bc


def test_f1_passes_when_distinct_bad_commits_in_window():
    rows = [
        {"RootCauseType": "unknown", "BadCommit": "",
         "UploadTime": now() - timedelta(days=1), "SearchRunId": "r-3"},
        {"RootCauseType": "bad_commit", "BadCommit": "commit_AAA",
         "UploadTime": now() - timedelta(days=8), "SearchRunId": "r-2"},
        {"RootCauseType": "bad_commit", "BadCommit": "commit_BBB",
         "UploadTime": now() - timedelta(days=20), "SearchRunId": "r-1"},
    ]
    client = make_kusto_client({"PRBinarySearchResult": rows})
    decision = _filter_1_existing_result(client, "SonicTestData", base_entry())
    assert decision.passed is True


def test_f1_logs_warning_and_fails_open_when_bad_commit_empty(caplog):
    """Data-quality signal: bad_commit row with empty BadCommit must warn,
    but still let the entry through."""
    client = make_kusto_client({
        "PRBinarySearchResult": [{
            "RootCauseType": "bad_commit",
            "BadCommit": "",
            "UploadTime": now(),
            "SearchRunId": "run-xyz",
        }],
    })
    with caplog.at_level(logging.WARNING, logger="presearch_filter"):
        decision = _filter_1_existing_result(client, "SonicTestData", base_entry())
    assert decision.passed is True
    assert any("empty BadCommit" in r.message for r in caplog.records)


def test_f1_passes_when_no_history():
    client = make_kusto_client({"PRBinarySearchResult": []})
    decision = _filter_1_existing_result(client, "SonicTestData", base_entry())
    assert decision.passed is True


# ---------------------------------------------------------------------------
# F2 historical pass rate
# ---------------------------------------------------------------------------

def test_f2_skips_flaky_test_with_high_pass_rate():
    client = make_kusto_client({
        "V2TestCases": [{"TotalRuns": 300, "Passes": 297}],  # 99 % > 98 %
    })
    decision = _filter_2_historical_pass_rate(client, "SonicTestData", base_entry())
    assert decision.passed is False
    assert decision.skipped_by == "F2_HIGH_PASS_RATE"
    assert decision.details["pass_rate"] == pytest.approx(0.99)


def test_f2_passes_when_pass_rate_below_98():
    client = make_kusto_client({
        "V2TestCases": [{"TotalRuns": 300, "Passes": 285}],  # 95 %
    })
    decision = _filter_2_historical_pass_rate(client, "SonicTestData", base_entry())
    assert decision.passed is True


def test_f2_passes_when_too_few_runs():
    client = make_kusto_client({
        "V2TestCases": [{"TotalRuns": F2_MIN_RUNS - 1, "Passes": F2_MIN_RUNS - 1}],
    })
    decision = _filter_2_historical_pass_rate(client, "SonicTestData", base_entry())
    assert decision.passed is True


# ---------------------------------------------------------------------------
# F3 circuit breaker
# ---------------------------------------------------------------------------

def test_f3_skips_when_last_N_results_all_unknown():
    client = make_kusto_client({
        "PRBinarySearchResult": [{"RootCauseType": "unknown"}
                                 for _ in range(F3_MAX_UNKNOWN_SEARCHES)],
    })
    decision = _filter_3_circuit_breaker(client, "SonicTestData", base_entry())
    assert decision.passed is False
    assert decision.skipped_by == "F3_CIRCUIT_BREAKER"
    assert decision.details["consecutive_unknowns"] == F3_MAX_UNKNOWN_SEARCHES


def test_f3_passes_when_streak_is_broken_by_bad_commit():
    rows = [{"RootCauseType": "unknown"} for _ in range(F3_MAX_UNKNOWN_SEARCHES - 1)]
    rows.insert(F3_MAX_UNKNOWN_SEARCHES // 2, {"RootCauseType": "bad_commit"})
    client = make_kusto_client({"PRBinarySearchResult": rows})
    decision = _filter_3_circuit_breaker(client, "SonicTestData", base_entry())
    assert decision.passed is True


def test_f3_passes_with_fewer_than_threshold_results():
    client = make_kusto_client({
        "PRBinarySearchResult": [{"RootCauseType": "unknown"}
                                 for _ in range(F3_MAX_UNKNOWN_SEARCHES - 1)],
    })
    decision = _filter_3_circuit_breaker(client, "SonicTestData", base_entry())
    assert decision.passed is True


# ---------------------------------------------------------------------------
# F4 pre-existing failure
# ---------------------------------------------------------------------------

def test_f4_skips_long_running_pre_existing_failure():
    t_now = now()
    client = make_kusto_client({"V2TestCases": [{
        "TotalRuns": 50,
        "Failures": 45,                 # 90 % > 80 % threshold
        "OldestFail": t_now - timedelta(days=F4_PREEXISTING_DAYS + 1),
        "NewestFail": t_now,
    }]})
    decision = _filter_4_preexisting_failure(client, "SonicTestData", base_entry())
    assert decision.passed is False
    assert decision.skipped_by == "F4_PREEXISTING_FAILURE"


def test_f4_passes_for_recent_failure_window():
    t_now = now()
    client = make_kusto_client({"V2TestCases": [{
        "TotalRuns": 10,
        "Failures": 9,
        "OldestFail": t_now - timedelta(days=1),
        "NewestFail": t_now,
    }]})
    decision = _filter_4_preexisting_failure(client, "SonicTestData", base_entry())
    assert decision.passed is True


def test_f4_passes_when_previously_clean_then_newly_failing():
    """Regression bug guard: a test that was clean for ~28 days and only
    started failing 2 days ago must NOT be classified pre-existing, even
    though the *earliest* run in the 30-day window is 28 days old.

    The old code computed span from min/max(StartTime) over all runs and
    false-skipped this case.  The fix uses min/max of *failing* StartTime.
    """
    t_now = now()
    client = make_kusto_client({"V2TestCases": [{
        "TotalRuns": 30,
        "Failures": 25,              # 83 % > 80 % threshold (eligible)
        "OldestFail": t_now - timedelta(days=2),
        "NewestFail": t_now,
    }]})
    decision = _filter_4_preexisting_failure(client, "SonicTestData", base_entry())
    assert decision.passed is True
    assert decision.skipped_by is None


def test_f4_passes_when_too_few_runs():
    t_now = now()
    client = make_kusto_client({"V2TestCases": [{
        "TotalRuns": F4_MIN_RUNS - 1,
        "Failures": F4_MIN_RUNS - 1,
        "OldestFail": t_now - timedelta(days=10),
        "NewestFail": t_now,
    }]})
    decision = _filter_4_preexisting_failure(client, "SonicTestData", base_entry())
    assert decision.passed is True


# ---------------------------------------------------------------------------
# Fail-open behaviour
# ---------------------------------------------------------------------------

def test_filter_fails_open_when_kusto_raises():
    client = MagicMock()
    client.execute.side_effect = RuntimeError("kusto down")
    assert _filter_1_existing_result(client, "db", base_entry()).passed is True
    assert _filter_2_historical_pass_rate(client, "db", base_entry()).passed is True
    assert _filter_3_circuit_breaker(client, "db", base_entry()).passed is True
    assert _filter_4_preexisting_failure(client, "db", base_entry()).passed is True


# ---------------------------------------------------------------------------
# Full chain via PreSearchFilter
# ---------------------------------------------------------------------------

def test_default_enabled_filters_excludes_F4():
    """F4 is opt-in until replay validates it."""
    assert "F4" not in DEFAULT_ENABLED_FILTERS
    assert {"F0", "F1", "F2", "F3"}.issubset(DEFAULT_ENABLED_FILTERS)


def test_default_chain_does_not_run_F4():
    """Even when F4 would fire, the default chain must let the entry
    through because F4 is not in the default enabled set."""
    t_now = now()
    client = make_kusto_client({
        "PRBinarySearchResult": [],
        "V2TestCases": [{"TotalRuns": 50, "Passes": 5,
                         "Failures": 45,
                         "OldestFail": t_now - timedelta(days=20),
                         "NewestFail": t_now}],
    })
    filt = PreSearchFilter(client, database="SonicTestData")
    decision = filt.evaluate(base_entry(testcase="test_brand_new"))
    assert decision.passed is True


def test_chain_short_circuits_on_first_skip():
    if not STATIC_BLOCKLIST:
        pytest.skip("STATIC_BLOCKLIST is empty in this build")
    tc, checker = next(iter(STATIC_BLOCKLIST))
    client = MagicMock()
    client.execute.side_effect = AssertionError("Kusto must not be called when F0 fires")
    filt = PreSearchFilter(client, database="SonicTestData")
    decision = filt.evaluate(base_entry(testcase=tc, checker=checker))
    assert decision.passed is False
    assert decision.skipped_by == "F0_STATIC_BLOCKLIST"


def test_chain_passes_clean_entry():
    t_now = now()
    client = make_kusto_client({
        "PRBinarySearchResult": [],
        "V2TestCases": [{"TotalRuns": 100, "Passes": 5,
                         "Failures": 5,
                         "OldestFail": t_now,
                         "NewestFail": t_now}],
    })
    filt = PreSearchFilter(
        client, database="SonicTestData",
        enabled_filters={"F0", "F1", "F2", "F3", "F4"},
    )
    decision = filt.evaluate(base_entry(testcase="test_brand_new"))
    assert decision.passed is True


def test_evaluate_many_splits_passes_and_skips():
    if not STATIC_BLOCKLIST:
        pytest.skip("STATIC_BLOCKLIST is empty in this build")
    tc, checker = next(iter(STATIC_BLOCKLIST))
    t_now = now()
    client = make_kusto_client({
        "PRBinarySearchResult": [],
        "V2TestCases": [{"TotalRuns": 100, "Passes": 5,
                         "Failures": 5,
                         "OldestFail": t_now,
                         "NewestFail": t_now}],
    })
    filt = PreSearchFilter(client, database="SonicTestData")
    entries = [
        base_entry(testcase="test_brand_new"),
        base_entry(testcase=tc, checker=checker),
    ]
    passing, skipped = filt.evaluate_many(entries)
    assert len(passing) == 1
    assert len(skipped) == 1
    assert skipped[0][1].skipped_by == "F0_STATIC_BLOCKLIST"


def test_enabled_filters_subset_skips_disabled_ones():
    """When only F0 is enabled, F1-F4 should not query Kusto at all."""
    client = MagicMock()
    client.execute.side_effect = AssertionError("Kusto must not be called when filter disabled")
    filt = PreSearchFilter(client, enabled_filters={"F0"})
    decision = filt.evaluate(base_entry(testcase="test_brand_new"))
    assert decision.passed is True
