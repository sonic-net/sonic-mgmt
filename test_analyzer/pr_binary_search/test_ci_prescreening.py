"""
Test script for CI pre-screening logic.

Simulates the full CI pre-screening flow with mock ADO API responses to verify
the narrowing algorithm works correctly without needing real ADO access.

Usage:
    cd test_analyzer/pr_binary_search
    python test_ci_prescreening.py
"""
import sys
import uuid
import logging
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta

# Ensure this directory is on the path so we can import project modules.
sys.path.insert(0, ".")

from pr_binary_search import (  # noqa: E402
    map_ci_builds_to_commits,
    narrow_with_ci_prescreening,
    process_failure_entry,
)

logging.basicConfig(level=logging.INFO, format="[%(threadName)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_commits(n, bad_index, start_date="2026-03-11T00:00:00Z"):
    """Generate *n* fake commits.  Commit at *bad_index* is the first bad one."""
    base = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
    commits = []
    for i in range(n):
        sha = f"commit_{i:04d}"
        date = (base + timedelta(hours=i * 4)).strftime("%Y-%m-%dT%H:%M:%SZ")
        commits.append({"sha": sha, "date": date, "message": f"msg {i}"})
    return commits, bad_index


def make_ci_builds(commit_indices, commits):
    """Create fake CI build dicts for commits at the given indices."""
    builds = []
    for idx in commit_indices:
        c = commits[idx]
        builds.append({
            "id": 90000 + idx,
            "sourceVersion": c["sha"],
            "result": "succeeded",
            "finishTime": c["date"],
            "_links": {"web": {"href": f"https://fake.dev.azure.com/build/{90000 + idx}"}},
        })
    return builds


def make_mock_client(commits, bad_index, ci_build_indices):
    """Return a mock AzureDevOpsClient wired up for CI prescreening.

    - ``fetch_completed_ci_builds`` returns builds at the given indices.
    - ``queue_build``/``poll_pipeline_details`` simulate test results based
      on ``bad_index`` — commits at or after bad_index are treated as *bad*.
    """
    ci_builds = make_ci_builds(ci_build_indices, commits)
    sha_to_idx = {c["sha"]: i for i, c in enumerate(commits)}

    client = MagicMock()
    client.fetch_completed_ci_builds.return_value = ci_builds

    run_counter = [10000]

    def fake_queue_build(pipeline_id, payload, max_retries=3):
        run_counter[0] += 1
        return {"id": run_counter[0], "_links": {"web": {"href": f"https://fake/{run_counter[0]}"}}}

    client.queue_build.side_effect = fake_queue_build

    def fake_poll_pipeline_details(runs, timeout=21600, check_interval=60):
        details = {}
        for run in runs:
            commit = run.commit
            idx = sha_to_idx.get(commit, -1)
            is_bad = idx >= bad_index if idx >= 0 else None
            details[commit] = {
                "is_bad": is_bad,
                "run_id": run.run_id,
                "run_url": run.run_url,
                "status": "completed",
                "result": "failed" if is_bad else "succeeded",
            }
        return details

    client.poll_pipeline_details.side_effect = fake_poll_pipeline_details
    client.extract_test_plan_ids.return_value = []
    return client


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_map_ci_builds_to_commits():
    """map_ci_builds_to_commits should return only matching builds, sorted."""
    commits, _ = make_commits(20, 10)
    ci_builds = make_ci_builds([3, 7, 12, 18], commits)
    # Add a build whose sourceVersion is NOT in the commit list.
    ci_builds.append({"id": 99999, "sourceVersion": "nonexistent_sha", "result": "succeeded"})

    mapped = map_ci_builds_to_commits(ci_builds, commits)
    assert len(mapped) == 4, f"Expected 4 mapped, got {len(mapped)}"
    assert [idx for idx, _, _ in mapped] == [3, 7, 12, 18]
    print("  PASS: map_ci_builds_to_commits")


def test_narrow_basic():
    """100 commits, bad at 45, CI builds every 10 commits → should narrow significantly."""
    n, bad_idx = 100, 45
    commits, _ = make_commits(n, bad_idx)
    ci_build_indices = list(range(5, n, 10))  # [5, 15, 25, 35, 45, 55, 65, 75, 85, 95]

    client = make_mock_client(commits, bad_idx, ci_build_indices)

    result_json = {
        "repo": "sonic-net/sonic-buildimage",
        "branch": "master",
        "commits": commits,
        "test_scripts": {"SomeChecker": ["tests/some_test.py"]},
        "analyzer_run_id": str(uuid.uuid4()),
        "trigger_type": "BaselineTest",
        "checker": "SomeChecker",
        "file_path": "tests/some_test.py",
        "module_path": "some_module",
        "testcase": "test_something",
    }

    narrowed, ci_cache, exec_recs, tp_recs = narrow_with_ci_prescreening(
        client=client,
        result_json=result_json,
        max_parallel=3,
        test_pipeline_id=3320,
        search_run_id=str(uuid.uuid4()),
        ci_pipeline_definition_id=1,
    )

    print(f"  Original commits: {n}")
    print(f"  CI builds tested: {len(ci_build_indices)}")
    print(f"  Narrowed to: {len(narrowed)} commits")
    print(f"  CI cache entries: {len(ci_cache)}")
    print(f"  Execution records: {len(exec_recs)}")

    # The narrowed range should contain the bad commit and be much smaller.
    narrowed_shas = {c["sha"] for c in narrowed}
    assert commits[bad_idx]["sha"] in narrowed_shas, "Bad commit must be in narrowed range"
    assert len(narrowed) < n, f"Narrowed range ({len(narrowed)}) should be < original ({n})"

    # Bad commit index 45 matches CI build at 45; last good CI build is at 35.
    # Narrowed range should be commits 36..45 → 10 commits.
    assert len(narrowed) <= 15, f"Expected ≤15 narrowed commits, got {len(narrowed)}"
    print("  PASS: test_narrow_basic")


def test_narrow_bad_at_start():
    """Bad commit at the very start — all CI commits are bad."""
    n, bad_idx = 50, 0
    commits, _ = make_commits(n, bad_idx)
    ci_build_indices = [5, 15, 25, 35, 45]

    client = make_mock_client(commits, bad_idx, ci_build_indices)
    result_json = {
        "repo": "sonic-net/sonic-buildimage",
        "branch": "master",
        "commits": commits,
        "test_scripts": {"C": ["t.py"]},
        "trigger_type": "BaselineTest",
        "checker": "C",
        "file_path": "t.py",
        "module_path": "m",
        "testcase": "test_x",
    }

    narrowed, ci_cache, _, _ = narrow_with_ci_prescreening(
        client=client,
        result_json=result_json,
        max_parallel=3,
        test_pipeline_id=3320,
        search_run_id=str(uuid.uuid4()),
        ci_pipeline_definition_id=1,
    )

    narrowed_shas = {c["sha"] for c in narrowed}
    assert commits[bad_idx]["sha"] in narrowed_shas, "Bad commit must be in narrowed range"
    # Since first CI build at index 5 is already bad, narrowed should be 0..5 = 6 commits.
    print(f"  Narrowed to: {len(narrowed)} commits (bad at start)")
    assert len(narrowed) <= 10
    print("  PASS: test_narrow_bad_at_start")


def test_narrow_no_bad():
    """All commits are good — should return the full list."""
    n = 50
    bad_idx = n + 100  # effectively no bad commit
    commits, _ = make_commits(n, bad_idx)
    ci_build_indices = [5, 15, 25, 35, 45]

    client = make_mock_client(commits, bad_idx, ci_build_indices)
    result_json = {
        "repo": "sonic-net/sonic-buildimage",
        "branch": "master",
        "commits": commits,
        "test_scripts": {"C": ["t.py"]},
        "trigger_type": "BaselineTest",
        "checker": "C",
        "file_path": "t.py",
        "module_path": "m",
        "testcase": "test_x",
    }

    narrowed, ci_cache, _, _ = narrow_with_ci_prescreening(
        client=client,
        result_json=result_json,
        max_parallel=3,
        test_pipeline_id=3320,
        search_run_id=str(uuid.uuid4()),
        ci_pipeline_definition_id=1,
    )

    print(f"  Narrowed to: {len(narrowed)} (no bad -> full range)")
    assert len(narrowed) == n, "No bad commit → should return full list"
    print("  PASS: test_narrow_no_bad")


def test_narrow_few_ci_builds():
    """Fewer than MIN_CI_BUILDS_FOR_PRESCREENING → skip prescreening."""
    n, bad_idx = 50, 25
    commits, _ = make_commits(n, bad_idx)
    ci_build_indices = [20]  # only 1 CI build

    client = make_mock_client(commits, bad_idx, ci_build_indices)
    result_json = {
        "repo": "sonic-net/sonic-buildimage",
        "branch": "master",
        "commits": commits,
        "test_scripts": {"C": ["t.py"]},
        "trigger_type": "BaselineTest",
        "checker": "C",
        "file_path": "t.py",
        "module_path": "m",
        "testcase": "test_x",
    }

    narrowed, ci_cache, _, _ = narrow_with_ci_prescreening(
        client=client,
        result_json=result_json,
        max_parallel=3,
        test_pipeline_id=3320,
        search_run_id=str(uuid.uuid4()),
        ci_pipeline_definition_id=1,
    )

    assert len(narrowed) == n, "Too few CI builds → should return full list"
    print("  PASS: test_narrow_few_ci_builds")


def test_process_failure_entry_integration():
    """End-to-end: process_failure_entry with CI prescreening enabled.

    Verifies that fewer VS images are built compared to without prescreening.
    """
    n, bad_idx = 80, 52
    commits, _ = make_commits(n, bad_idx)
    ci_build_indices = list(range(5, n, 10))  # 8 CI builds

    sha_to_idx = {c["sha"]: i for i, c in enumerate(commits)}

    client = make_mock_client(commits, bad_idx, ci_build_indices)

    # Track which commits get individually built.
    individually_built = []

    def fake_prebuild(client, repo, branch, commit_ids, build_pipeline_id, build_queue_parallel):
        individually_built.extend(commit_ids)
        build_map = {}
        for sha in commit_ids:
            idx = sha_to_idx.get(sha, -1)
            build_map[sha] = {
                "is_bad": False,
                "run_id": 50000 + idx,
                "run_url": f"https://fake/build/{50000 + idx}",
                "status": "completed",
                "result": "succeeded",
            }
        return build_map

    result_json = {
        "repo": "sonic-net/sonic-buildimage",
        "branch": "master",
        "commits": commits,
        "test_scripts": {"C": ["t.py"]},
        "analyzer_run_id": str(uuid.uuid4()),
        "trigger_type": "BaselineTest",
        "checker": "C",
        "file_path": "t.py",
        "module_path": "m",
        "testcase": "test_x",
    }

    with patch("pr_binary_search.prebuild_commits_for_repo", side_effect=fake_prebuild):
        entry_key, result, build_map = process_failure_entry(
            client=client,
            result_json=result_json,
            entry_key="test#0",
            max_parallel=3,
            test_pipeline_id=3320,
            build_pipeline_id=3332,
            build_queue_parallel=10,
            search_run_id=str(uuid.uuid4()),
            enable_ci_prescreening=True,
            ci_pipeline_definition_id=1,
        )

    print(f"  Total commits: {n}")
    print(f"  Individually built: {len(individually_built)} (instead of {n})")
    print(f"  Bad commit found: {result.get('bad_commit')}")
    print(f"  Search completed: {result.get('search_completed')}")

    ci_stages = [r for r in result.get("execution_records", []) if r.get("Stage") == "ci_prescreening"]
    build_stages = [r for r in result.get("execution_records", []) if r.get("Stage") == "build"]
    test_stages = [r for r in result.get("execution_records", []) if r.get("Stage") == "test"]
    print(f"  Execution records: {len(ci_stages)} ci_prescreening, {len(build_stages)} build, {len(test_stages)} test")

    assert len(individually_built) < n, (
        f"With prescreening, should build fewer than {n} images, built {len(individually_built)}"
    )
    assert result.get("bad_commit") == commits[bad_idx]["sha"], (
        f"Expected bad commit {commits[bad_idx]['sha']}, got {result.get('bad_commit')}"
    )
    print("  PASS: test_process_failure_entry_integration")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main():
    tests = [
        ("map_ci_builds_to_commits", test_map_ci_builds_to_commits),
        ("narrow_basic (100 commits, bad@45)", test_narrow_basic),
        ("narrow_bad_at_start", test_narrow_bad_at_start),
        ("narrow_no_bad", test_narrow_no_bad),
        ("narrow_few_ci_builds", test_narrow_few_ci_builds),
        ("process_failure_entry integration", test_process_failure_entry_integration),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        print(f"\n--- {name} ---")
        try:
            fn()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  FAIL: {e}")
            import traceback
            traceback.print_exc()

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    if failed:
        sys.exit(1)
    print("All tests passed!")


if __name__ == "__main__":
    main()
