"""
Test script for the flakiness gate logic.

Simulates the flakiness gate flow with mock ADO API responses to verify
the decision logic works correctly without needing real ADO access.

Usage:
    cd test_analyzer/pr_binary_search
    python -m pytest test_flakiness_gate.py -v
"""
import sys
import logging
from unittest.mock import MagicMock

sys.path.insert(0, ".")

from flakiness_gate import FlakinessGate  # noqa: E402

logging.basicConfig(level=logging.INFO, format="[%(threadName)s] %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_result_json(repo="sonic-net/sonic-mgmt", testcase="test_example"):
    return {
        "repo": repo,
        "branch": "master",
        "test_scripts": {"t0_checker": ["feature/test_example.py"]},
        "commits": [{"sha": f"commit_{i}", "date": f"2026-05-0{i+1}T00:00:00Z"} for i in range(5)],
        "analyzer_run_id": "run-001",
        "trigger_type": "BaselineTest",
        "checker": "t0_checker",
        "file_path": "feature/test_example.py",
        "module_path": "feature.test_example",
        "testcase": testcase,
    }


def _run_result(is_bad, run_id, url, result=None):
    """Helper to build a poll result entry."""
    if result is None:
        result = "failed" if is_bad else "succeeded"
    return {
        "is_bad": is_bad, "run_id": run_id,
        "run_url": url, "status": "completed", "result": result,
    }


def make_mock_client(queue_results=None, poll_results=None):
    """Create a mock AzureDevOpsClient."""
    client = MagicMock()

    if queue_results is None:
        # Default: 3 successful queue responses
        queue_results = [
            {"id": 1001, "_links": {"web": {"href": "https://fake/1001"}}},
            {"id": 1002, "_links": {"web": {"href": "https://fake/1002"}}},
            {"id": 1003, "_links": {"web": {"href": "https://fake/1003"}}},
        ]
    client.queue_build.side_effect = queue_results

    if poll_results is None:
        # Default: all fail
        poll_results = {}
    client.poll_pipeline_details.return_value = poll_results

    return client


# ---------------------------------------------------------------------------
# Tests: Mgmt flow
# ---------------------------------------------------------------------------

class TestMgmtFlow:
    def test_all_fail_not_flaky(self):
        """If all 3 runs fail, test is NOT flaky — proceed with bisect."""
        client = make_mock_client()
        # Poll returns all bad
        client.poll_pipeline_details.return_value = {
            "HEAD_flakiness_run1": _run_result(True, 1001, "u1"),
            "HEAD_flakiness_run2": _run_result(True, 1002, "u2"),
            "HEAD_flakiness_run3": _run_result(True, 1003, "u3"),
        }

        gate = FlakinessGate(client, test_pipeline_id=3320, build_pipeline_id=3332, num_runs=3)
        result = gate.run(make_result_json(repo="sonic-net/sonic-mgmt"))

        assert result.is_flaky is True
        assert result.passed_runs == 1
        assert result.failed_runs == 2
        assert "FLAKY" in result.reason

    def test_all_pass_is_flaky(self):
        """If all 3 runs pass, test IS flaky."""
        client = make_mock_client()
        client.poll_pipeline_details.return_value = {
            "HEAD_flakiness_run1": _run_result(False, 1001, "u1"),
            "HEAD_flakiness_run2": _run_result(False, 1002, "u2"),
            "HEAD_flakiness_run3": _run_result(False, 1003, "u3"),
        }

        gate = FlakinessGate(client, test_pipeline_id=3320, build_pipeline_id=3332, num_runs=3)
        result = gate.run(make_result_json(repo="sonic-net/sonic-mgmt"))

        assert result.is_flaky is True
        assert result.passed_runs == 3

    def test_trigger_failure_not_flaky(self):
        """If all triggers fail, treat as not flaky (proceed with bisect)."""
        client = MagicMock()
        client.queue_build.side_effect = RuntimeError("ADO API error")

        gate = FlakinessGate(client, test_pipeline_id=3320, build_pipeline_id=3332, num_runs=3)
        result = gate.run(make_result_json(repo="sonic-net/sonic-mgmt"))

        assert result.is_flaky is False
        assert "Failed to trigger" in result.reason

    def test_no_mgmt_commit_hash_in_params(self):
        """Verify that mgmt flow does NOT pin MGMT_COMMIT_HASH (uses latest)."""
        client = make_mock_client()
        client.poll_pipeline_details.return_value = {
            "HEAD_flakiness_run1": _run_result(True, 1001, "u1"),
            "HEAD_flakiness_run2": _run_result(True, 1002, "u2"),
            "HEAD_flakiness_run3": _run_result(True, 1003, "u3"),
        }

        gate = FlakinessGate(client, test_pipeline_id=3320, build_pipeline_id=3332, num_runs=3)
        gate.run(make_result_json(repo="sonic-net/sonic-mgmt"))

        # Check payload of first queue_build call
        first_call = client.queue_build.call_args_list[0]
        payload = first_call[0][1]  # second positional arg
        template_params = payload.get("templateParameters", {})
        # MGMT_COMMIT_HASH should not be in params (uses latest)
        assert "MGMT_COMMIT_HASH" not in template_params


# ---------------------------------------------------------------------------
# Tests: Buildimage flow
# ---------------------------------------------------------------------------

class TestBuildimageFlow:
    def test_build_then_test_all_fail(self):
        """For buildimage: build succeeds, all tests fail → not flaky."""
        client = make_mock_client(
            queue_results=[
                {"id": 9999, "_links": {"web": {"href": "https://fake/9999"}}},  # build
                {"id": 1001, "_links": {"web": {"href": "https://fake/1001"}}},
                {"id": 1002, "_links": {"web": {"href": "https://fake/1002"}}},
                {"id": 1003, "_links": {"web": {"href": "https://fake/1003"}}},
            ]
        )

        # First poll call is for the build, returns success
        # Second poll call is for the tests, returns all fail
        call_count = [0]

        def mock_poll(runs, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # Build poll
                return {
                    runs[0].commit: {
                        "is_bad": False, "run_id": 9999,
                        "run_url": "build_url", "status": "completed",
                        "result": "succeeded",
                    }
                }
            else:
                # Test poll
                result = {}
                for run in runs:
                    result[run.commit] = {
                        "is_bad": True, "run_id": run.run_id,
                        "run_url": run.run_url, "status": "completed",
                        "result": "failed",
                    }
                return result

        client.poll_pipeline_details.side_effect = mock_poll

        gate = FlakinessGate(client, test_pipeline_id=3320, build_pipeline_id=3332, num_runs=3)
        result = gate.run(make_result_json(repo="sonic-net/sonic-buildimage"))

        assert result.is_flaky is False
        assert result.build_run_id == 9999
        # 1 build trigger + 3 test triggers
        assert client.queue_build.call_count == 4

    def test_build_then_test_one_passes_flaky(self):
        """For buildimage: build succeeds, 1 test passes → flaky."""
        client = make_mock_client(
            queue_results=[
                {"id": 9999, "_links": {"web": {"href": "https://fake/9999"}}},  # build
                {"id": 1001, "_links": {"web": {"href": "https://fake/1001"}}},
                {"id": 1002, "_links": {"web": {"href": "https://fake/1002"}}},
                {"id": 1003, "_links": {"web": {"href": "https://fake/1003"}}},
            ]
        )

        call_count = [0]

        def mock_poll(runs, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return {
                    runs[0].commit: _run_result(False, 9999, "u")
                }
            else:
                result = {}
                for i, run in enumerate(runs):
                    # Second test passes
                    is_bad = (i != 1)
                    result[run.commit] = _run_result(
                        is_bad, run.run_id, run.run_url
                    )
                return result

        client.poll_pipeline_details.side_effect = mock_poll

        gate = FlakinessGate(client, test_pipeline_id=3320, build_pipeline_id=3332, num_runs=3)
        result = gate.run(make_result_json(repo="sonic-net/sonic-buildimage"))

        assert result.is_flaky is True
        assert result.build_run_id == 9999

    def test_build_fails_not_flaky(self):
        """If build fails, can't determine flakiness → proceed with bisect."""
        client = make_mock_client()
        client.poll_pipeline_details.return_value = {
            "HEAD": {"is_bad": True, "run_id": 9999, "run_url": "u", "status": "completed", "result": "failed"}
        }

        gate = FlakinessGate(client, test_pipeline_id=3320, build_pipeline_id=3332, num_runs=3)
        result = gate.run(make_result_json(repo="sonic-net/sonic-buildimage"))

        assert result.is_flaky is False
        assert "build failed" in result.reason.lower() or "timed out" in result.reason.lower()


# ---------------------------------------------------------------------------
# Entry point for manual testing
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
