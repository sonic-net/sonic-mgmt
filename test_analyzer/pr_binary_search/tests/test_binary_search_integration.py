"""
Integration tests for the PR binary search pipeline.

These tests verify that:
1. DynamicParallelBisect correctly identifies regression commits across all positions
2. execute_binary_search correctly uses build_cache (including pre-existing batched CI builds)
3. Failed/missing/unknown builds are handled without triggering unnecessary test pipelines
4. The 'batched CI first' optimization: build_cache pre-populated from existing CI builds
   is consumed correctly by the binary search, avoiding redundant image builds

All AzDO pipeline calls are mocked â€” no real pipelines are triggered.

Run with:
    cd <repo_root>
    pytest test_analyzer/pr_binary_search/tests/test_binary_search_integration.py -v
"""

import sys
import os
import math
import pytest
from typing import Dict, List, Optional
from unittest.mock import MagicMock, patch

# Make pr_binary_search package importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binary_plan import DynamicParallelBisect, choose_optimal_segments, compute_indices  # noqa: E402
from pr_binary_search import (  # noqa: E402
    execute_binary_search, derive_include_jobs, remap_test_scripts_for_pipeline,
    get_pr_url_for_commit, _commit_pr_cache,
)
from schemas import PipelineRunParameters  # noqa: E402


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
# Shared test helpers
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

def make_commits(n: int) -> List[str]:
    """Generate n deterministic fake commit SHAs."""
    return [f"deadbeef{i:02d}aabbccdd" for i in range(n)]


def make_result_json(commits: List[str], repo: str = "sonic-net/sonic-buildimage") -> dict:
    """Build a minimal failure-info record as consumed by execute_binary_search.

    Uses t1-multi-asic_checker (the real Kusto checker for counterpoll multi-asic tests)
    so remap_test_scripts_for_pipeline and derive_include_jobs behave as in production:
      - IMPACT_AREA_INFO gets remapped key t1_checker (pipeline-compatible)
      - INCLUDE_JOBS is derived as t1_multi_asic_job (not "all")
    """
    return {
        "repo": repo,
        "branch": "master",
        # t1-multi-asic_checker: remapped → t1_checker for IMPACT_AREA_INFO,
        # and derives INCLUDE_JOBS=t1_multi_asic_job.
        "test_scripts": {"t1-multi-asic_checker": ["platform_tests/counterpoll/test_counterpoll_watermark.py"]},
        "commits": [{"sha": sha} for sha in commits],
        "analyzer_run_id": "test-run-id-mock",
        "trigger_type": "BaselineTest",
        "checker": "multi-asic-t1",
        "file_path": "platform_tests/counterpoll/test_counterpoll_watermark.py",
        "module_path": "platform_tests.counterpoll.test_counterpoll_watermark",
        "testcase": "test_counterpoll_queue_watermark_pg_drop[vlab-08]",
    }


def make_build_cache(
    commits: List[str],
    bad_indices: set = None,
    missing_indices: set = None,
    unknown_indices: set = None,
    custom_run_ids: dict = None,
) -> dict:
    """
    Build a build_cache dict keyed by commit SHA.

    Args:
        commits:        list of commit SHAs
        bad_indices:    indices whose image build failed (is_bad=True)
        missing_indices: indices to omit from cache (simulates no pre-build)
        unknown_indices: indices where result is indeterminate (is_bad=None)
        custom_run_ids: {index: run_id} â€” override the default run_id for that index
                        (use this to inject pre-existing batched CI build IDs)
    """
    bad_indices = bad_indices or set()
    missing_indices = missing_indices or set()
    unknown_indices = unknown_indices or set()
    custom_run_ids = custom_run_ids or {}

    cache = {}
    for i, sha in enumerate(commits):
        if i in missing_indices:
            continue
        run_id = custom_run_ids.get(i, 9000 + i)
        if i in bad_indices:
            cache[sha] = {
                "is_bad": True,
                "run_id": run_id,
                "run_url": f"https://dev.azure.com/mssonic/build/_build/results?buildId={run_id}",
                "status": "completed",
                "result": "failed",
            }
        elif i in unknown_indices:
            cache[sha] = {
                "is_bad": None,
                "run_id": run_id,
                "run_url": f"https://dev.azure.com/mssonic/build/_build/results?buildId={run_id}",
                "status": "completed",
                "result": "unknown",
            }
        else:
            cache[sha] = {
                "is_bad": False,
                "run_id": run_id,
                "run_url": f"https://dev.azure.com/mssonic/build/_build/results?buildId={run_id}",
                "status": "completed",
                "result": "succeeded",
            }
    return cache


def make_mock_client(test_results_by_commit: Dict[str, bool]) -> MagicMock:
    """
    Create a mock AzureDevOpsClient that resolves test results from a lookup dict.

    poll_pipeline_details() immediately returns the pre-determined result for each
    commit, eliminating real network calls and polling delays.
    """
    client = MagicMock()

    def _poll_details(pipeline_runs, **kwargs):
        details = {}
        for run in pipeline_runs:
            is_bad = test_results_by_commit.get(run.commit, False)
            details[run.commit] = {
                "is_bad": is_bad,
                "run_id": run.run_id,
                "run_url": run.run_url,
                "status": "completed",
                "result": "failed" if is_bad else "succeeded",
            }
        return details

    client.poll_pipeline_details.side_effect = _poll_details
    client.extract_test_plan_ids.return_value = []
    return client


def make_trigger_side_effect(run_id_start: int = 5000):
    """
    Returns a side_effect callable for the patched trigger_pipeline that
    assigns incrementing run IDs without making real HTTP calls.
    """
    counter = [run_id_start]

    def _trigger(client, branch, commit, stage, pipeline_id, params):
        run_id = counter[0]
        counter[0] += 1
        return PipelineRunParameters(
            commit=commit,
            run_id=run_id,
            run_url=f"https://dev.azure.com/mssonic/build/_build/results?buildId={run_id}",
            stage=stage,
        )

    return _trigger


def run_execute_binary_search(
    commits: List[str],
    test_results_by_commit: Dict[str, bool],
    build_cache: Optional[dict] = None,
    repo: str = "sonic-net/sonic-buildimage",
    max_parallel: int = 3,
):
    """
    Helper: runs execute_binary_search with mocked AzDO client and trigger_pipeline.

    Returns (result_dict, mock_client, mock_trigger).
    """
    result_json = make_result_json(commits, repo)
    client = make_mock_client(test_results_by_commit)

    with patch("pr_binary_search.trigger_pipeline", side_effect=make_trigger_side_effect()) as mock_trigger:
        result = execute_binary_search(
            client=client,
            result_json=result_json,
            max_parallel=max_parallel,
            test_pipeline_id=3320,
            build_cache=build_cache,
            search_run_id="mock-search-run-id",
        )
    return result, client, mock_trigger


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
# Part 1 â€” DynamicParallelBisect: pure algorithm correctness
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

class TestDynamicParallelBisect:

    def _bisect(self, commits, bad_from_index, max_parallel=3):
        b = DynamicParallelBisect(commits, max_parallel=max_parallel)
        return b.find_bad_commit_auto(lambda c: commits.index(c) >= bad_from_index)

    def test_regression_at_first_commit(self):
        commits = make_commits(7)
        assert self._bisect(commits, bad_from_index=0) == commits[0]

    def test_regression_at_last_commit(self):
        commits = make_commits(7)
        assert self._bisect(commits, bad_from_index=6) == commits[6]

    def test_regression_at_middle(self):
        commits = make_commits(7)
        assert self._bisect(commits, bad_from_index=3) == commits[3]

    def test_regression_at_index_1(self):
        commits = make_commits(7)
        assert self._bisect(commits, bad_from_index=1) == commits[1]

    def test_regression_at_second_to_last(self):
        commits = make_commits(7)
        assert self._bisect(commits, bad_from_index=5) == commits[5]

    def test_all_commits_good_returns_none(self):
        commits = make_commits(7)
        b = DynamicParallelBisect(commits, max_parallel=3)
        result = b.find_bad_commit_auto(lambda c: False)
        assert result is None

    def test_single_commit_bad(self):
        commits = ["sha_only"]
        b = DynamicParallelBisect(commits, max_parallel=1)
        assert b.find_bad_commit_auto(lambda c: True) == "sha_only"

    def test_single_commit_good(self):
        commits = ["sha_only"]
        b = DynamicParallelBisect(commits, max_parallel=1)
        assert b.find_bad_commit_auto(lambda c: False) is None

    def test_two_commits_first_bad(self):
        commits = make_commits(2)
        assert self._bisect(commits, bad_from_index=0) == commits[0]

    def test_two_commits_second_bad(self):
        commits = make_commits(2)
        assert self._bisect(commits, bad_from_index=1) == commits[1]

    @pytest.mark.parametrize("n,bad_idx", [
        (8, 0), (8, 3), (8, 7),
        (15, 7), (15, 14),
        (30, 0), (30, 15), (30, 29),
    ])
    def test_parametric_regression_positions(self, n, bad_idx):
        commits = make_commits(n)
        result = self._bisect(commits, bad_from_index=bad_idx)
        assert result == commits[bad_idx], (
            f"n={n}, bad_idx={bad_idx}: expected commits[{bad_idx}]={commits[bad_idx]}, got {result}"
        )

    def test_converges_in_log_n_rounds(self):
        """Binary search should converge in O(log n) rounds even with parallelism=1."""
        commits = make_commits(64)
        BAD_IDX = 37
        b = DynamicParallelBisect(commits, max_parallel=1)
        rounds = 0
        while True:
            plan = b.get_next_test_commits()
            if plan is None:
                break
            results = {c: (commits.index(c) >= BAD_IDX) for c in plan["tests"]}
            status = b.submit_test_results(results)
            rounds += 1
            if status["finished"]:
                break
        result, _ = b.get_result()
        assert result == commits[BAD_IDX]
        assert rounds <= math.ceil(math.log2(len(commits))) + 2  # +2 for edge rounding

    def test_parallel_reduces_rounds(self):
        """Higher max_parallel should converge in fewer rounds than max_parallel=1."""
        commits = make_commits(32)
        BAD_IDX = 20

        def count_rounds(max_parallel):
            b = DynamicParallelBisect(commits, max_parallel=max_parallel)
            rounds = 0
            while True:
                plan = b.get_next_test_commits()
                if plan is None:
                    break
                results = {c: (commits.index(c) >= BAD_IDX) for c in plan["tests"]}
                status = b.submit_test_results(results)
                rounds += 1
                if status["finished"]:
                    break
            result, _ = b.get_result()
            assert result == commits[BAD_IDX], f"max_parallel={max_parallel} gave wrong result"
            return rounds

        rounds_serial = count_rounds(max_parallel=1)
        rounds_parallel = count_rounds(max_parallel=5)
        assert rounds_parallel <= rounds_serial, (
            f"Parallel ({rounds_parallel} rounds) should not take more rounds than serial ({rounds_serial})"
        )

    def test_submit_results_reports_eliminated_commits(self):
        """submit_test_results should identify which commits are no longer in range."""
        commits = make_commits(8)
        b = DynamicParallelBisect(commits, max_parallel=4)
        plan = b.get_next_test_commits()
        assert plan is not None
        # All tested commits are good â†’ they should be eliminated
        results = {c: False for c in plan["tests"]}
        status = b.submit_test_results(results)
        new_range = status.get("new_range_commits") or []
        for c in plan["tests"]:
            assert c not in new_range, f"{c} should have been eliminated after all-good round"

    def test_get_search_status_fields(self):
        """get_search_status returns expected keys."""
        commits = make_commits(5)
        b = DynamicParallelBisect(commits, max_parallel=2)
        status = b.get_search_status()
        for key in ("finished", "result", "current_round", "current_range",
                    "current_range_commits", "remaining_commits", "max_parallel"):
            assert key in status, f"Missing key: {key}"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
# Part 2 â€” compute_indices / choose_optimal_segments helpers
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

class TestBinaryPlanHelpers:

    def test_compute_indices_single_segment_returns_empty(self):
        assert compute_indices(0, 9, 1) == []

    def test_compute_indices_two_segments(self):
        # [0..9] into 2 segments â†’ boundary at midpoint
        indices = compute_indices(0, 9, 2)
        assert len(indices) == 1
        assert 0 < indices[0] < 9

    def test_compute_indices_are_sorted_and_in_range(self):
        for left, right, f in [(0, 9, 3), (2, 10, 4), (5, 15, 5)]:
            indices = compute_indices(left, right, f)
            assert indices == sorted(indices), "Indices should be sorted"
            assert all(left <= i <= right for i in indices), "All indices must be within [left, right]"

    def test_compute_indices_count(self):
        # f segments â†’ f-1 boundary points
        for f in range(2, 8):
            indices = compute_indices(0, 20, f)
            assert len(indices) == f - 1, f"Expected {f-1} indices for {f} segments, got {len(indices)}"

    def test_choose_optimal_segments_trivial(self):
        assert choose_optimal_segments(1, 5) == 1
        assert choose_optimal_segments(2, 5) == 2

    def test_choose_optimal_segments_bounded_by_max_parallel(self):
        for mp in (1, 2, 3, 5):
            segs = choose_optimal_segments(100, mp)
            # segments can produce at most max_parallel+1 boundary groups
            assert segs <= mp + 1, f"Segments {segs} exceeded max_parallel+1={mp+1}"


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
# Part 3 â€” execute_binary_search: integration with mocked AzDO client
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

class TestExecuteBinarySearch:

    BUILDIMAGE_REPO = "sonic-net/sonic-buildimage"
    MGMT_REPO = "sonic-net/sonic-mgmt"

    # â”€â”€ basic correctness â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def test_finds_regression_at_index_3_of_7(self):
        commits = make_commits(7)
        BAD_IDX = 3
        build_cache = make_build_cache(commits)
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        result, _, mock_trigger = run_execute_binary_search(commits, test_results, build_cache)

        assert result["bad_commit"] == commits[BAD_IDX]
        assert result["search_completed"] is True
        assert mock_trigger.call_count > 0  # Some test pipelines were triggered

    def test_finds_regression_at_first_commit(self):
        commits = make_commits(7)
        build_cache = make_build_cache(commits)
        test_results = {c: True for c in commits}  # All bad

        result, _, _ = run_execute_binary_search(commits, test_results, build_cache)

        assert result["bad_commit"] == commits[0]
        assert result["search_completed"] is True

    def test_finds_regression_at_last_commit(self):
        commits = make_commits(7)
        build_cache = make_build_cache(commits)
        test_results = {c: (c == commits[-1]) for c in commits}

        result, _, _ = run_execute_binary_search(commits, test_results, build_cache)

        assert result["bad_commit"] == commits[-1]
        assert result["search_completed"] is True

    def test_no_regression_when_all_tests_pass(self):
        commits = make_commits(5)
        build_cache = make_build_cache(commits)
        test_results = {c: False for c in commits}

        result, _, _ = run_execute_binary_search(commits, test_results, build_cache)

        assert result["bad_commit"] is None
        assert result["search_completed"] is True

    # â”€â”€ build-cache handling â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def test_failed_build_is_treated_as_bad_without_triggering_test(self):
        """A commit whose image build failed â†’ immediately marked bad, no test pipeline triggered."""
        commits = make_commits(5)
        # Build failed at index 2 (and all after)
        build_cache = make_build_cache(commits, bad_indices={2, 3, 4})
        test_results = {commits[0]: False, commits[1]: False}

        result, _, mock_trigger = run_execute_binary_search(commits, test_results, build_cache)

        # Record must be present with build_failed_skip_test
        skip_records = [r for r in result["execution_records"] if r.get("Verdict") == "build_failed_skip_test"]
        assert len(skip_records) >= 1, "Expected build_failed_skip_test records"

        # trigger_pipeline must NOT be called for the failed-build commits
        triggered_commits = {call.args[2] for call in mock_trigger.call_args_list}
        for sha in triggered_commits:
            idx = commits.index(sha)
            assert idx not in {2, 3, 4}, (
                f"commit at index {idx} had a failed build but was still triggered for testing"
            )

    def test_missing_build_cache_entry_records_error(self):
        """Commit absent from build_cache â†’ missing_prebuild_mapping recorded, test not run."""
        commits = make_commits(4)
        # Index 1 missing from cache
        build_cache = make_build_cache(commits, missing_indices={1})
        test_results = {commits[0]: False, commits[2]: True, commits[3]: True}

        result, _, _ = run_execute_binary_search(commits, test_results, build_cache)

        missing = [r for r in result["execution_records"] if r.get("Verdict") == "missing_prebuild_mapping"]
        assert len(missing) >= 1, "Expected missing_prebuild_mapping record"

    def test_unknown_build_result_records_skip(self):
        """Commit with is_bad=None â†’ unknown_build_skip_test recorded, test not run."""
        commits = make_commits(4)
        build_cache = make_build_cache(commits, unknown_indices={1})
        test_results = {commits[0]: False, commits[2]: True, commits[3]: True}

        result, _, _ = run_execute_binary_search(commits, test_results, build_cache)

        unknown_records = [r for r in result["execution_records"] if r.get("Verdict") == "unknown_build_skip_test"]
        assert len(unknown_records) >= 1, "Expected unknown_build_skip_test record"

    def test_all_builds_failed_identifies_first_commit_no_tests_triggered(self):
        """When every image build failed, no test pipelines run and first commit is flagged."""
        commits = make_commits(4)
        build_cache = make_build_cache(commits, bad_indices=set(range(len(commits))))
        test_results = {}

        result, _, mock_trigger = run_execute_binary_search(commits, test_results, build_cache)

        assert mock_trigger.call_count == 0, "No test pipelines should fire when all builds failed"
        # The binary search should converge to the first bad commit
        assert result["bad_commit"] == commits[0]

    # â”€â”€ MGMT repo (no build cache needed) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

    def test_mgmt_repo_uses_commit_hash_not_kvm_id(self):
        """For sonic-mgmt binary search: no build_cache; MGMT_COMMIT_HASH is set in params."""
        commits = make_commits(5)
        BAD_IDX = 2
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        result, _, mock_trigger = run_execute_binary_search(
            commits, test_results,
            build_cache=None,
            repo=self.MGMT_REPO,
        )

        assert result["bad_commit"] == commits[BAD_IDX]
        assert result["search_completed"] is True

        # Verify MGMT_COMMIT_HASH is set and KVM_BUILD_ID is absent
        for call_args in mock_trigger.call_args_list:
            params = call_args.args[5]
            payload = params.to_payload()
            assert "MGMT_COMMIT_HASH" in payload, "MGMT_COMMIT_HASH must be set for mgmt repo"
            assert "KVM_BUILD_ID" not in payload, "KVM_BUILD_ID must not appear for mgmt repo"

    # â”€â”€ batched CI pre-filter scenario â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”

    def test_batched_ci_builds_reused_as_build_cache(self):
        """
        Simulate the 'batched CI first' optimization:

        build_cache is pre-populated with KVM build IDs from the EXISTING batched CI
        pipeline (pipeline 1) for commits that have CI images, plus fresh custom builds
        for the remaining commits.  The binary search must reuse these IDs without
        rebuilding images.

        Layout (8 commits, regression at index 4):
          - Commits 0, 3, 7  â†’ pre-existing batched CI KVM IDs (e.g. 1059448, 1059697, 1060100)
          - Commits 1,2,4,5,6 â†’ freshly built images (IDs from pipeline 3319)
          - Test: commits 0â€“3 pass, commits 4â€“7 fail
        """
        commits = make_commits(8)
        BAD_IDX = 4

        BATCHED_CI_RUN_IDS = {0: 1059448, 3: 1059697, 7: 1060100}
        FRESH_BUILD_RUN_IDS = {1: 1076262, 2: 1076263, 4: 1076265, 5: 1076266, 6: 1076267}

        all_custom_run_ids = {**BATCHED_CI_RUN_IDS, **FRESH_BUILD_RUN_IDS}
        build_cache = make_build_cache(commits, custom_run_ids=all_custom_run_ids)

        # Annotate batched CI entries with a marker (extra field, ignored by pipeline)
        for i in BATCHED_CI_RUN_IDS:
            build_cache[commits[i]]["source"] = "batched_ci"

        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        result, _, mock_trigger = run_execute_binary_search(commits, test_results, build_cache, max_parallel=3)

        assert result["bad_commit"] == commits[BAD_IDX], (
            f"Expected commits[{BAD_IDX}]={commits[BAD_IDX]}, got {result['bad_commit']}"
        )
        assert result["search_completed"] is True

        # Verify the correct KVM build IDs were forwarded to the test pipeline
        test_trigger_calls = mock_trigger.call_args_list
        for call_args in test_trigger_calls:
            params = call_args.args[5]
            payload = params.to_payload()
            kvm_id = int(payload.get("KVM_BUILD_ID", 0))
            # Every KVM ID passed to a test must come from our build cache
            all_expected_run_ids = set(all_custom_run_ids.values())
            assert kvm_id in all_expected_run_ids, (
                f"Unexpected KVM_BUILD_ID {kvm_id} â€” not in the build cache"
            )

    def test_batched_ci_with_narrowed_range(self):
        """
        Batched CI builds exist only for the boundary commits (good/bad ends).
        The algorithm should test the mid-points and converge using existing IDs
        for those boundary checks, minimising new image builds.

        10 commits, regression at index 5.
        Batched CI provides IDs for indices 0 (good) and 9 (bad).
        Fresh builds cover indices 1â€“8.
        """
        commits = make_commits(10)
        BAD_IDX = 5

        custom_run_ids = {
            0: 1059448,  # batched CI â€” good
            9: 1059697,  # batched CI â€” bad
            **{i: 1076260 + i for i in range(1, 9)},  # fresh builds
        }
        build_cache = make_build_cache(commits, custom_run_ids=custom_run_ids)
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        result, _, _ = run_execute_binary_search(commits, test_results, build_cache, max_parallel=3)

        assert result["bad_commit"] == commits[BAD_IDX]
        assert result["search_completed"] is True

    # â”€â”€ execution record schema compliance â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â

    def test_execution_records_have_required_fields(self):
        """Every execution record must contain the required Kusto schema columns."""
        commits = make_commits(5)
        BAD_IDX = 2
        build_cache = make_build_cache(commits)
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        result, _, _ = run_execute_binary_search(commits, test_results, build_cache)

        required = {
            "SearchRunId", "AnalyzerRunId", "FailureJoinKey", "SourceRepo", "Branch",
            "CheckerType", "FilePath", "TestCase", "RoundNumber", "CommitSha",
            "Stage", "Verdict", "IsBad", "UploadTime",
        }
        for rec in result["execution_records"]:
            missing = required - set(rec.keys())
            assert not missing, f"Record missing fields: {missing}\n  Record: {rec}"

    def test_result_dict_has_required_top_level_keys(self):
        """execute_binary_search result must contain all top-level keys."""
        commits = make_commits(3)
        build_cache = make_build_cache(commits)
        test_results = {c: False for c in commits}

        result, _, _ = run_execute_binary_search(commits, test_results, build_cache)

        for key in ("bad_commit", "search_completed", "total_rounds",
                    "execution_records", "test_plan_records", "repo"):
            assert key in result, f"Missing top-level key: {key}"

    def test_kvm_build_id_matches_build_cache_run_id(self):
        """
        When a test pipeline is triggered, the KVM_BUILD_ID parameter must equal
        the run_id stored in the build_cache for that commit.
        """
        commits = make_commits(4)
        BAD_IDX = 2
        build_cache = make_build_cache(commits)
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        _, _, mock_trigger = run_execute_binary_search(commits, test_results, build_cache)

        for call_args in mock_trigger.call_args_list:
            triggered_commit = call_args.args[2]
            params = call_args.args[5]
            payload = params.to_payload()
            expected_kvm_id = str(build_cache[triggered_commit]["run_id"])
            actual_kvm_id = payload.get("KVM_BUILD_ID")
            assert actual_kvm_id == expected_kvm_id, (
                f"commit {triggered_commit}: expected KVM_BUILD_ID={expected_kvm_id}, "
                f"got {actual_kvm_id}"
            )

    def test_build_branch_is_set_in_all_test_triggers(self):
        """BUILD_BRANCH must be non-empty in every triggered test pipeline payload.

        An empty BUILD_BRANCH causes calculate_instance_number.py to fail with
        'argument --branch: expected one argument'.
        """
        commits = make_commits(4)
        BAD_IDX = 2
        build_cache = make_build_cache(commits)
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        _, _, mock_trigger = run_execute_binary_search(commits, test_results, build_cache)

        assert mock_trigger.call_count > 0, "Expected at least one test pipeline trigger"
        for call_args in mock_trigger.call_args_list:
            payload = call_args.args[5].to_payload()
            branch = payload.get("BUILD_BRANCH", "")
            assert branch, (
                f"BUILD_BRANCH is empty — calculate_instance_number.py will fail. "
                f"Full payload: {payload}"
            )

    # ── INCLUDE_JOBS and checker remapping ────────────────────────────────────

    def test_multi_asic_checker_derives_multi_asic_include_jobs(self):
        """t1-multi-asic_checker must derive INCLUDE_JOBS=t1_multi_asic_job (not 'all').

        Passing INCLUDE_JOBS='all' runs t1-lag and vpp jobs unnecessarily.
        The checker-to-jobs mapping must produce the narrower job set.
        """
        test_scripts = {"t1-multi-asic_checker": ["platform_tests/counterpoll/test_counterpoll_watermark.py"]}
        include_jobs = derive_include_jobs(test_scripts)
        assert include_jobs == "t1_multi_asic_job", (
            f"Expected 't1_multi_asic_job', got '{include_jobs}'. "
            "This causes t1-lag and vpp jobs to run unnecessarily."
        )

    def test_multi_asic_checker_remapped_for_pipeline(self):
        """t1-multi-asic_checker must be remapped to t1_checker in IMPACT_AREA_INFO.

        The pipeline's get-impacted-area step recognises t1_checker, not
        t1-multi-asic_checker.
        """
        test_scripts = {"t1-multi-asic_checker": ["platform_tests/counterpoll/test_counterpoll_watermark.py"]}
        remapped = remap_test_scripts_for_pipeline(test_scripts)
        assert "t1_checker" in remapped, (
            f"t1-multi-asic_checker was not remapped to t1_checker. Got: {remapped}"
        )
        assert "t1-multi-asic_checker" not in remapped, (
            "Original key t1-multi-asic_checker should be removed after remapping"
        )
        assert remapped["t1_checker"] == test_scripts["t1-multi-asic_checker"]

    def test_include_jobs_set_in_triggered_payload(self):
        """INCLUDE_JOBS derived from t1-multi-asic_checker must appear in the pipeline payload."""
        commits = make_commits(3)
        BAD_IDX = 1
        build_cache = make_build_cache(commits)
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        _, _, mock_trigger = run_execute_binary_search(commits, test_results, build_cache)

        for call_args in mock_trigger.call_args_list:
            payload = call_args.args[5].to_payload()
            assert payload.get("INCLUDE_JOBS") == "t1_multi_asic_job", (
                f"Expected INCLUDE_JOBS=t1_multi_asic_job, got '{payload.get('INCLUDE_JOBS')}'. "
                "t1-lag and vpp jobs will run unnecessarily."
            )

    @pytest.mark.parametrize("checker,expected_jobs", [
        ("t0_checker",              "t0_job"),
        ("t1_checker",              "t1_job"),
        ("t1-multi-asic_checker",   "t1_multi_asic_job"),
        ("dualtor_checker",         "dualtor_job"),
        ("t2_checker",              "t2_job"),
    ])
    def test_checker_to_include_jobs_mapping(self, checker, expected_jobs):
        """Each checker type must derive the correct INCLUDE_JOBS value."""
        result = derive_include_jobs({checker: ["some/test.py"]})
        assert result == expected_jobs, (
            f"checker={checker}: expected INCLUDE_JOBS='{expected_jobs}', got '{result}'"
        )


# ──────────────────────────────────────────────────────────────────────
# Part 4 – round-by-round on-demand builds
# ──────────────────────────────────────────────────────────────────────

def run_execute_binary_search_with_round_builds(
    commits: List[str],
    test_results_by_commit: Dict[str, bool],
    ci_build_cache: Optional[dict] = None,
    max_parallel: int = 3,
    build_pipeline_id: int = 3332,
):
    """
    Run execute_binary_search with build_pipeline_id set (round-by-round mode).

    prebuild_commits_for_repo is patched to return synthetic build-cache entries
    without making real network calls.  Returns (result, mock_client, mock_trigger,
    prebuild_calls) where prebuild_calls is the list of commit-id lists passed to
    each per-round prebuild invocation.
    """
    commits_with_meta = [{"sha": sha} for sha in commits]
    result_json = {
        "repo": "sonic-net/sonic-buildimage",
        "branch": "master",
        "test_scripts": {"t1-multi-asic_checker": ["test.py"]},
        "commits": commits_with_meta,
        "analyzer_run_id": "mock-run",
        "trigger_type": "BaselineTest",
        "checker": "t1-multi-asic_checker",
        "file_path": "test.py",
        "module_path": "test",
        "testcase": "test_case",
    }
    client = make_mock_client(test_results_by_commit)

    prebuild_calls = []

    def _fake_prebuild(client, repo, branch, commit_ids,
                       build_pipeline_id, build_queue_parallel):
        prebuild_calls.append(list(commit_ids))
        built = {}
        for i, sha in enumerate(commit_ids):
            run_id = 8000 + commits.index(sha)
            built[sha] = {
                "is_bad": False,
                "run_id": run_id,
                "run_url": f"https://fake/build/{run_id}",
                "status": "completed",
                "result": "succeeded",
            }
        return built

    with patch("pr_binary_search.trigger_pipeline",
               side_effect=make_trigger_side_effect()) as mock_trigger, \
         patch("pr_binary_search.prebuild_commits_for_repo",
               side_effect=_fake_prebuild):
        result = execute_binary_search(
            client=client,
            result_json=result_json,
            max_parallel=max_parallel,
            test_pipeline_id=3320,
            build_cache=dict(ci_build_cache) if ci_build_cache else None,
            search_run_id="mock-search-id",
            build_pipeline_id=build_pipeline_id,
            build_queue_parallel=2,
        )
    return result, client, mock_trigger, prebuild_calls


class TestRoundByRoundBuilds:
    """execute_binary_search with build_pipeline_id triggers per-round on-demand builds."""

    def test_builds_only_round_commits_not_all_upfront(self):
        """Each prebuild call must only contain commits for that round, not all commits."""
        commits = make_commits(8)
        BAD_IDX = 4
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        result, _, _, prebuild_calls = run_execute_binary_search_with_round_builds(
            commits, test_results, max_parallel=3
        )

        assert result["search_completed"] is True
        assert result["bad_commit"] == commits[BAD_IDX]

        # Each individual prebuild call must be ≤ max_parallel commits.
        for call_commits in prebuild_calls:
            assert len(call_commits) <= 3, (
                f"Prebuild triggered {len(call_commits)} commits in one round; "
                "expected at most max_parallel=3"
            )

        # Total unique commits built must be << 8 (only visited commits).
        all_built = {c for call in prebuild_calls for c in call}
        assert len(all_built) < len(commits), (
            "Round-by-round build should visit fewer commits than the full set"
        )

    def test_ci_prescreened_commits_not_rebuilt(self):
        """Commits already in ci_build_cache must not be passed to prebuild_commits_for_repo."""
        commits = make_commits(6)
        BAD_IDX = 3
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        # Pre-seed cache with commits[2] (a CI build) and commits[4]
        ci_cache = {
            commits[2]: {"is_bad": False, "run_id": 7002, "run_url": "u", "status": "completed", "result": "succeeded"},
            commits[4]: {"is_bad": False, "run_id": 7004, "run_url": "u", "status": "completed", "result": "succeeded"},
        }

        _, _, _, prebuild_calls = run_execute_binary_search_with_round_builds(
            commits, test_results, ci_build_cache=ci_cache, max_parallel=3
        )

        built_via_pipeline = {c for call in prebuild_calls for c in call}
        # Commits already in ci_cache must not be re-built.
        for cached_sha in ci_cache:
            assert cached_sha not in built_via_pipeline, (
                f"Commit {cached_sha} was in ci_build_cache but got re-built unnecessarily"
            )

    def test_build_stage_records_emitted_per_round(self):
        """Build-stage execution records must be present for every on-demand built commit."""
        commits = make_commits(5)
        BAD_IDX = 2
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        result, _, _, prebuild_calls = run_execute_binary_search_with_round_builds(
            commits, test_results, max_parallel=2
        )

        built_commits = {c for call in prebuild_calls for c in call}
        build_records = [r for r in result["execution_records"] if r["Stage"] == "build"]
        built_in_records = {r["CommitSha"] for r in build_records}

        assert built_commits == built_in_records, (
            f"Build records don't match built commits.\n"
            f"  Built: {built_commits}\n  In records: {built_in_records}"
        )
        for rec in build_records:
            assert rec["RoundNumber"] >= 1, "Build records must carry the actual round number"

    def test_build_failure_mid_round_marks_commit_bad(self):
        """If a per-round build fails (is_bad=True), the commit must be marked bad without testing."""
        commits = make_commits(5)
        BAD_IDX = 2
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        commits_with_meta = [{"sha": sha} for sha in commits]
        result_json = {
            "repo": "sonic-net/sonic-buildimage",
            "branch": "master",
            "test_scripts": {"t1-multi-asic_checker": ["test.py"]},
            "commits": commits_with_meta,
            "analyzer_run_id": "mock",
            "trigger_type": "BaselineTest",
            "checker": "t1-multi-asic_checker",
            "file_path": "test.py",
            "module_path": "test",
            "testcase": "tc",
        }
        client = make_mock_client(test_results)

        def _fake_prebuild_with_failure(client, repo, branch, commit_ids,
                                        build_pipeline_id, build_queue_parallel):
            built = {}
            for sha in commit_ids:
                idx = commits.index(sha)
                run_id = 8000 + idx
                # Simulate build failure for commits[BAD_IDX]
                if idx == BAD_IDX:
                    built[sha] = {
                        "is_bad": True, "run_id": run_id,
                        "run_url": f"u/{run_id}", "status": "completed", "result": "failed",
                    }
                else:
                    built[sha] = {
                        "is_bad": False, "run_id": run_id,
                        "run_url": f"u/{run_id}", "status": "completed", "result": "succeeded",
                    }
            return built

        with patch("pr_binary_search.trigger_pipeline",
                   side_effect=make_trigger_side_effect()) as mock_trigger, \
             patch("pr_binary_search.prebuild_commits_for_repo",
                   side_effect=_fake_prebuild_with_failure):
            result = execute_binary_search(
                client=client,
                result_json=result_json,
                max_parallel=2,
                test_pipeline_id=3320,
                build_cache=None,
                search_run_id="mock",
                build_pipeline_id=3332,
                build_queue_parallel=2,
            )

        # Commit with failed build must be identified as bad.
        assert result["bad_commit"] == commits[BAD_IDX]
        # No test pipeline should be triggered for the build-failed commit.
        triggered_commits = {call.args[2] for call in mock_trigger.call_args_list}
        assert commits[BAD_IDX] not in triggered_commits, (
            "Test pipeline must not fire for a commit whose build failed"
        )

    def test_build_cache_returned_in_result(self):
        """execute_binary_search must include accumulated build_cache in its result dict."""
        commits = make_commits(4)
        test_results = {c: False for c in commits}

        result, _, _, _ = run_execute_binary_search_with_round_builds(
            commits, test_results, max_parallel=2
        )

        assert "build_cache" in result, "result must contain 'build_cache'"
        # All visited commits must appear in the returned build_cache.
        build_records = [r for r in result["execution_records"] if r["Stage"] == "build"]
        visited = {r["CommitSha"] for r in build_records}
        for sha in visited:
            assert sha in result["build_cache"], f"{sha} missing from returned build_cache"

    def test_failed_cache_entries_are_retried_next_round(self):
        """Commits with a failed build status in the cache must be retried in subsequent rounds,
        not silently skipped as if they had a valid image."""
        commits = make_commits(4)
        BAD_IDX = 2
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        # Seed the cache with a queue_error entry for commits[1] — it should be rebuilt.
        error_entry = {
            "is_bad": None,
            "run_id": None,
            "run_url": None,
            "status": "queue_error",
            "result": "previous failure",
        }
        ci_cache = {commits[1]: error_entry}

        prebuild_calls = []

        def _fake_prebuild(client, repo, branch, commit_ids,
                           build_pipeline_id, build_queue_parallel):
            prebuild_calls.append(list(commit_ids))
            built = {}
            for sha in commit_ids:
                idx = commits.index(sha)
                run_id = 8000 + idx
                built[sha] = {
                    "is_bad": False, "run_id": run_id,
                    "run_url": f"https://fake/build/{run_id}",
                    "status": "completed", "result": "succeeded",
                }
            return built

        commits_with_meta = [{"sha": sha} for sha in commits]
        result_json = {
            "repo": "sonic-net/sonic-buildimage",
            "branch": "master",
            "test_scripts": {"t1-multi-asic_checker": ["test.py"]},
            "commits": commits_with_meta,
            "analyzer_run_id": "mock",
            "trigger_type": "BaselineTest",
            "checker": "t1-multi-asic_checker",
            "file_path": "test.py",
            "module_path": "test",
            "testcase": "tc",
        }
        client = make_mock_client(test_results)

        with patch("pr_binary_search.trigger_pipeline",
                   side_effect=make_trigger_side_effect()), \
             patch("pr_binary_search.prebuild_commits_for_repo",
                   side_effect=_fake_prebuild):
            execute_binary_search(
                client=client,
                result_json=result_json,
                max_parallel=2,
                test_pipeline_id=3320,
                build_cache=dict(ci_cache),
                search_run_id="mock",
                build_pipeline_id=3332,
                build_queue_parallel=2,
            )

        all_rebuilt = {c for call in prebuild_calls for c in call}
        # commits[1] had a queue_error; it must have been retried.
        assert commits[1] in all_rebuilt, (
            "commits[1] had a 'queue_error' cache entry but was NOT retried. "
            "Failed builds must be retried when selected again in a later round."
        )

    def test_prebuild_exception_handled_gracefully(self):
        """If prebuild_commits_for_repo raises, the search must not abort;
        affected commits should receive queue_error entries and be treated as bad."""
        commits = make_commits(4)
        BAD_IDX = 2
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        def _raising_prebuild(client, repo, branch, commit_ids,
                              build_pipeline_id, build_queue_parallel):
            raise RuntimeError("Network timeout during queue")

        commits_with_meta = [{"sha": sha} for sha in commits]
        result_json = {
            "repo": "sonic-net/sonic-buildimage",
            "branch": "master",
            "test_scripts": {"t1-multi-asic_checker": ["test.py"]},
            "commits": commits_with_meta,
            "analyzer_run_id": "mock",
            "trigger_type": "BaselineTest",
            "checker": "t1-multi-asic_checker",
            "file_path": "test.py",
            "module_path": "test",
            "testcase": "tc",
        }
        client = make_mock_client(test_results)

        with patch("pr_binary_search.trigger_pipeline",
                   side_effect=make_trigger_side_effect()), \
             patch("pr_binary_search.prebuild_commits_for_repo",
                   side_effect=_raising_prebuild):
            # Must not raise — should return a result dict
            result = execute_binary_search(
                client=client,
                result_json=result_json,
                max_parallel=2,
                test_pipeline_id=3320,
                build_cache=None,
                search_run_id="mock",
                build_pipeline_id=3332,
                build_queue_parallel=2,
            )

        assert isinstance(result, dict), "execute_binary_search must return a dict even on prebuild failure"
        # Build records must capture the queue_error status, not be missing.
        build_records = [r for r in result.get("execution_records", []) if r["Stage"] == "build"]
        assert build_records, "Build-stage records must be emitted even when prebuild raises"
        for rec in build_records:
            assert rec["Status"] == "queue_error", (
                f"Expected Status='queue_error' for failed prebuild, got '{rec['Status']}'"
            )


# ──────────────────────────────────────────────────────────────────────
# Part 5 – OVERRIDE_PARAMS / KVM_IMAGE_BUILD_PIPELINE_ID
# ──────────────────────────────────────────────────────────────────────

def make_ci_build_cache(commits, ci_pipeline_definition_id=1):
    """Return a build cache where every entry is flagged as a CI prescreening hit."""
    cache = {}
    for i, sha in enumerate(commits):
        run_id = 9000 + i
        cache[sha] = {
            "is_bad": False,
            "run_id": run_id,
            "run_url": f"https://fake/ci/{run_id}",
            "status": "completed",
            "result": "succeeded",
            "ci_prescreening": True,
            "pipeline_definition_id": ci_pipeline_definition_id,
        }
    return cache


class TestOverrideParamsKvmPipelineId:
    """KVM_IMAGE_BUILD_PIPELINE_ID must be set in OVERRIDE_PARAMS for CI-sourced builds."""

    def test_ci_sourced_builds_set_kvm_pipeline_id(self):
        """When a commit's build came from a CI pipeline, OVERRIDE_PARAMS must include
        KVM_IMAGE_BUILD_PIPELINE_ID pointing to that pipeline, so the test scheduler
        fetches the image from the right pipeline (not defaulting to the VS build pipeline)."""
        CI_PIPELINE_ID = 1
        commits = make_commits(4)
        BAD_IDX = 2
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        ci_cache = make_ci_build_cache(commits, ci_pipeline_definition_id=CI_PIPELINE_ID)
        commits_with_meta = [{"sha": sha} for sha in commits]
        result_json = {
            "repo": "sonic-net/sonic-buildimage",
            "branch": "master",
            "test_scripts": {"t1-multi-asic_checker": ["test.py"]},
            "commits": commits_with_meta,
            "analyzer_run_id": "mock",
            "trigger_type": "BaselineTest",
            "checker": "t1-multi-asic_checker",
            "file_path": "test.py",
            "module_path": "test",
            "testcase": "tc",
        }
        client = make_mock_client(test_results)

        with patch("pr_binary_search.trigger_pipeline",
                   side_effect=make_trigger_side_effect()) as mock_trigger:
            execute_binary_search(
                client=client,
                result_json=result_json,
                max_parallel=2,
                test_pipeline_id=3320,
                build_cache=dict(ci_cache),
                search_run_id="mock",
            )

        assert mock_trigger.called, "trigger_pipeline should have been called"
        for call_args in mock_trigger.call_args_list:
            params = call_args.args[5]
            override = params.OVERRIDE_PARAMS or {}
            assert override.get("KVM_IMAGE_BUILD_PIPELINE_ID") == str(CI_PIPELINE_ID), (
                f"Expected OVERRIDE_PARAMS[KVM_IMAGE_BUILD_PIPELINE_ID]='{CI_PIPELINE_ID}', "
                f"got OVERRIDE_PARAMS={override!r}. "
                "The test scheduler will try to fetch the VS image from the wrong pipeline."
            )

    def test_non_ci_sourced_builds_do_not_set_override(self):
        """Commits built by the VS image build pipeline must NOT receive an OVERRIDE_PARAMS
        (or the value should be None), to avoid overriding the correct default."""
        commits = make_commits(4)
        BAD_IDX = 2
        test_results = {c: (commits.index(c) >= BAD_IDX) for c in commits}

        # Regular (non-CI) build cache — no ci_prescreening flag
        regular_cache = make_build_cache(commits)
        commits_with_meta = [{"sha": sha} for sha in commits]
        result_json = {
            "repo": "sonic-net/sonic-buildimage",
            "branch": "master",
            "test_scripts": {"t1-multi-asic_checker": ["test.py"]},
            "commits": commits_with_meta,
            "analyzer_run_id": "mock",
            "trigger_type": "BaselineTest",
            "checker": "t1-multi-asic_checker",
            "file_path": "test.py",
            "module_path": "test",
            "testcase": "tc",
        }
        client = make_mock_client(test_results)

        with patch("pr_binary_search.trigger_pipeline",
                   side_effect=make_trigger_side_effect()) as mock_trigger:
            execute_binary_search(
                client=client,
                result_json=result_json,
                max_parallel=2,
                test_pipeline_id=3320,
                build_cache=dict(regular_cache),
                search_run_id="mock",
            )

        assert mock_trigger.called
        for call_args in mock_trigger.call_args_list:
            params = call_args.args[5]
            assert not params.OVERRIDE_PARAMS, (
                f"Non-CI build must not set OVERRIDE_PARAMS, got {params.OVERRIDE_PARAMS!r}"
            )


# ---------------------------------------------------------------------------
# fetch_failure_info_from_kusto — skip-completed filtering
# ---------------------------------------------------------------------------

class TestFetchFailureInfoFromKusto:
    """Verify that fetch_failure_info_from_kusto skips already-completed episodes."""

    def _make_kusto_client(self, failure_rows):
        """Return a mock KustoClient whose execute_query returns *failure_rows*."""
        mock_result = MagicMock()
        mock_result.primary_results = [MagicMock()]
        mock_result.primary_results[0].to_dict.return_value = {"data": failure_rows}
        client = MagicMock()
        client.execute_query.return_value = mock_result
        return client

    def _capture_query(self, failure_rows):
        """Return (query_str, records) for a call with the given rows."""
        client = self._make_kusto_client(failure_rows)
        from pr_binary_search import fetch_failure_info_from_kusto
        records = fetch_failure_info_from_kusto(client, lookback_hours=12)
        query_str = client.execute_query.call_args[0][1]
        return query_str, records

    def test_skip_completed_uses_analyzer_run_id(self):
        """The skip subquery must filter by AnalyzerRunId — not FailureJoinKey — to avoid
        suppressing new regressions of the same test."""
        query, _ = self._capture_query([])
        assert "AnalyzerRunId" in query
        assert "SearchCompleted" in query
        assert "leftanti" in query

    def test_completed_filter_uses_result_table(self):
        """The skip subquery must reference PRBinarySearchResult."""
        query, _ = self._capture_query([])
        assert "PRBinarySearchResult" in query

    def test_failure_join_key_in_projection(self):
        """FailureJoinKey must be included in the projected columns."""
        query, _ = self._capture_query([])
        assert "FailureJoinKey" in query

    def test_records_returned_from_rows(self):
        """Records returned should match the rows the Kusto mock provides."""
        rows = [
            {"AnalyzerRunId": "aaa", "FailureJoinKey": "sonic-net/sonic-mgmt|master|PRTest|t0|f.py|m|test_foo",
             "SourceRepo": "sonic-net/sonic-mgmt",
             "Branch": "master", "TriggerType": "PRTest", "CheckerType": "t0_checker",
             "FilePath": "f.py", "ModulePath": "m", "TestCase": "test_foo",
             "Commits": [], "LikelyIssueClose": False, "RawFailureInfo": None},
        ]
        _, records = self._capture_query(rows)
        assert len(records) == 1
        assert records[0]["AnalyzerRunId"] == "aaa"
        assert records[0]["FailureJoinKey"] == "sonic-net/sonic-mgmt|master|PRTest|t0|f.py|m|test_foo"

    def test_raw_failure_info_json_string_is_parsed(self):
        """RawFailureInfo stored as a JSON string must be parsed into a dict."""
        import json
        raw = json.dumps({"test_scripts": {"t0_checker": ["f.py"]}})
        rows = [
            {"AnalyzerRunId": "bbb", "FailureJoinKey": "sonic-net/sonic-buildimage|master|PRTest|t0|f.py|m|test_bar",
             "SourceRepo": "sonic-net/sonic-buildimage",
             "Branch": "master", "TriggerType": "PRTest", "CheckerType": "t0_checker",
             "FilePath": "f.py", "ModulePath": "m", "TestCase": "test_bar",
             "Commits": [], "LikelyIssueClose": False, "RawFailureInfo": raw},
        ]
        _, records = self._capture_query(rows)
        assert isinstance(records[0]["RawFailureInfo"], dict)
        assert "test_scripts" in records[0]["RawFailureInfo"]

    def test_lookback_hours_appears_in_query(self):
        """Custom lookback_hours value must be reflected in the KQL query."""
        query, _ = self._capture_query([])
        assert "12h" in query

    def test_exact_failure_join_key_bypasses_lookback(self):
        """When exact_failure_join_key is set the time filter must be absent
        and the query must filter by FailureJoinKey with a take 1 limit."""
        client = self._make_kusto_client([])
        from pr_binary_search import fetch_failure_info_from_kusto
        fetch_failure_info_from_kusto(
            client,
            lookback_hours=12,
            exact_failure_join_key="sonic-net/sonic-mgmt|master|PRTest|t0|f.py|m|test_foo",
        )
        query = client.execute_query.call_args[0][1]
        assert "12h" not in query, "Lookback filter should be absent when exact key is provided"
        assert "FailureJoinKey ==" in query
        assert "take 1" in query

    def test_exact_analyzer_run_id_bypasses_lookback(self):
        """When exact_analyzer_run_id is set all rows for that batch are returned
        (no time filter, no take 1 limit — one batch can have many failure rows)."""
        client = self._make_kusto_client([])
        from pr_binary_search import fetch_failure_info_from_kusto
        fetch_failure_info_from_kusto(
            client,
            lookback_hours=12,
            exact_analyzer_run_id="batch-run-abc123",
        )
        query = client.execute_query.call_args[0][1]
        assert "12h" not in query, "Lookback filter should be absent when exact batch ID is provided"
        assert "AnalyzerRunId ==" in query
        assert "take 1" not in query, "No row limit — all failures in the batch should be returned"


# ──────────────────────────────────────────
# get_pr_url_for_commit tests
# ──────────────────────────────────────────

class TestGetPrUrlForCommit:
    """Tests for get_pr_url_for_commit() caching and error handling."""

    def setup_method(self):
        _commit_pr_cache.clear()

    @patch("pr_binary_search.GIT_API_TOKEN", "fake-token")
    @patch("pr_binary_search.requests.get")
    def test_caches_pr_url_on_success(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[{"html_url": "https://github.com/org/repo/pull/42"}]),
        )
        result = get_pr_url_for_commit("org/repo", "abc123")
        assert result == "https://github.com/org/repo/pull/42"
        assert _commit_pr_cache[("org/repo", "abc123")] == "https://github.com/org/repo/pull/42"
        # Second call should use cache, not API
        result2 = get_pr_url_for_commit("org/repo", "abc123")
        assert result2 == "https://github.com/org/repo/pull/42"
        assert mock_get.call_count == 1

    @patch("pr_binary_search.GIT_API_TOKEN", "fake-token")
    @patch("pr_binary_search.requests.get")
    def test_caches_none_for_empty_pr_list(self, mock_get):
        """200 with empty list should cache None to avoid repeated API calls."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value=[]),
        )
        result = get_pr_url_for_commit("org/repo", "no-pr-commit")
        assert result is None
        assert ("org/repo", "no-pr-commit") in _commit_pr_cache
        assert _commit_pr_cache[("org/repo", "no-pr-commit")] is None
        # Second call should use cache
        get_pr_url_for_commit("org/repo", "no-pr-commit")
        assert mock_get.call_count == 1

    @patch("pr_binary_search.GIT_API_TOKEN", "fake-token")
    @patch("pr_binary_search.requests.get")
    def test_does_not_cache_on_403_rate_limit(self, mock_get):
        """403 is often a GitHub rate-limit response and should not be cached."""
        mock_get.return_value = MagicMock(status_code=403)
        result = get_pr_url_for_commit("org/repo", "rate-limited")
        assert result is None
        assert ("org/repo", "rate-limited") not in _commit_pr_cache

    @patch("pr_binary_search.GIT_API_TOKEN", "fake-token")
    @patch("pr_binary_search.requests.get")
    def test_does_not_cache_on_429(self, mock_get):
        mock_get.return_value = MagicMock(status_code=429)
        result = get_pr_url_for_commit("org/repo", "throttled")
        assert result is None
        assert ("org/repo", "throttled") not in _commit_pr_cache

    @patch("pr_binary_search.GIT_API_TOKEN", "fake-token")
    @patch("pr_binary_search.requests.get")
    def test_caches_none_on_404(self, mock_get):
        """404 is a permanent error — commit doesn't exist — should be cached."""
        mock_get.return_value = MagicMock(status_code=404)
        result = get_pr_url_for_commit("org/repo", "missing-commit")
        assert result is None
        assert _commit_pr_cache[("org/repo", "missing-commit")] is None

    @patch("pr_binary_search.GIT_API_TOKEN", "fake-token")
    @patch("pr_binary_search.requests.get")
    def test_does_not_cache_on_server_error(self, mock_get):
        for code in [500, 502, 503, 504]:
            _commit_pr_cache.clear()
            mock_get.return_value = MagicMock(status_code=code)
            result = get_pr_url_for_commit("org/repo", "server-err")
            assert result is None
            assert ("org/repo", "server-err") not in _commit_pr_cache

    def test_returns_none_without_token(self):
        with patch("pr_binary_search.GIT_API_TOKEN", ""):
            result = get_pr_url_for_commit("org/repo", "abc123")
            assert result is None

    def test_returns_none_for_none_inputs(self):
        with patch("pr_binary_search.GIT_API_TOKEN", "fake-token"):
            assert get_pr_url_for_commit(None, "abc123") is None
            assert get_pr_url_for_commit("org/repo", None) is None
