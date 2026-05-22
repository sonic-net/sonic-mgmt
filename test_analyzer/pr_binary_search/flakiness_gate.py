"""
Flakiness Gate — Run 3 parallel tests with latest code before binary search
============================================================================

Before triggering binary search, verify the failure is reproducible by running
the test 3 times in parallel using the latest code (HEAD of master).

Strategy by source repository:
  - sonic-net/sonic-mgmt (mgmt issue):
      Run the test directly 3 times via the pre_defined_pr_test pipeline
      without pinning MGMT_COMMIT_HASH (uses HEAD of the failure's branch).

  - sonic-net/sonic-buildimage (image issue):
      Build a VS image from the latest buildimage commit on the failure's
      branch, then run the test 3 times using that image.

Decision logic:
  - If ANY of the 3 runs passes → test is FLAKY → skip binary search.
  - If ALL 3 runs fail → failure is reproducible → proceed with bisect.

Usage:
    from flakiness_gate import FlakinessGate

    gate = FlakinessGate(client, ...)
    result = gate.run(result_json)
    if result.is_flaky:
        # skip binary search for this entry
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from config import MGMT_REPO
from pipeline_triggers import AzureDevOpsClient, trigger_pipeline
from schemas import TestPipelineParameters, BuildPipelineParameters, PipelineRunParameters

logger = logging.getLogger(__name__)

# Defaults
DEFAULT_NUM_RUNS = 3
DEFAULT_RETRY_TIMES = "0"  # No retries — we want raw pass/fail signal
BUILD_REASON = "FlakinessGate"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FlakinessResult:
    """Outcome of the flakiness gate for one failure entry."""
    is_flaky: bool
    total_runs: int = 0
    passed_runs: int = 0
    failed_runs: int = 0
    error_runs: int = 0
    pipeline_run_ids: list[int] = field(default_factory=list)
    build_run_id: Optional[int] = None
    reason: str = ""
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Flakiness Gate
# ---------------------------------------------------------------------------

class FlakinessGate:
    """Run N parallel tests with latest code to detect flaky failures.

    For mgmt issues: run test directly with latest mgmt code.
    For image issues: build latest image first, then run tests.
    If any run passes → flaky → skip binary search.
    """

    def __init__(
        self,
        client: AzureDevOpsClient,
        test_pipeline_id: int,
        build_pipeline_id: int,
        num_runs: int = DEFAULT_NUM_RUNS,
        poll_timeout: int = 21600,
        poll_interval: int = 60,
    ):
        self.client = client
        self.test_pipeline_id = test_pipeline_id
        self.build_pipeline_id = build_pipeline_id
        self.num_runs = max(1, num_runs)
        self.poll_timeout = poll_timeout
        self.poll_interval = poll_interval

    def run(self, result_json: dict) -> FlakinessResult:
        """Execute the flakiness gate for a single failure entry.

        Args:
            result_json: Parsed failure entry dict with keys like
                repo, branch, test_scripts, commits, checker, etc.

        Returns:
            FlakinessResult indicating whether the test is flaky.
        """
        repo = result_json.get("repo", "")
        branch = result_json.get("branch", "master")

        if repo == MGMT_REPO:
            return self._run_mgmt(result_json, branch)
        else:
            return self._run_buildimage(result_json, branch)

    def _run_mgmt(self, result_json: dict, branch: str) -> FlakinessResult:
        """For mgmt issues: run test directly with latest master code."""
        test_scripts = result_json.get("test_scripts", {})

        logger.info(
            "Flakiness gate (mgmt): triggering %d parallel test runs "
            "with latest code for %s",
            self.num_runs, result_json.get("testcase", "unknown"),
        )

        # Trigger N test pipelines WITHOUT pinning MGMT_COMMIT_HASH
        # This uses HEAD of master — the latest test code
        runs = self._trigger_test_runs(
            branch=branch,
            test_scripts=test_scripts,
            kvm_build_id=None,
            mgmt_commit_hash=None,  # Use latest
        )

        if not runs:
            return FlakinessResult(
                is_flaky=False,
                reason="Failed to trigger any test pipelines — "
                       "proceeding with bisect.",
            )

        return self._poll_and_evaluate(runs)

    def _run_buildimage(self, result_json: dict, branch: str) -> FlakinessResult:
        """For buildimage issues: build latest image, then run tests."""
        test_scripts = result_json.get("test_scripts", {})

        logger.info(
            "Flakiness gate (buildimage): building latest image then "
            "triggering %d parallel test runs for %s",
            self.num_runs, result_json.get("testcase", "unknown"),
        )

        # Step 1: Build a VS image from the latest buildimage commit
        try:
            build_run = self._trigger_latest_build(branch)
        except Exception as e:
            reason = (f"Failed to trigger image build: {e} — "
                      f"proceeding with bisect.")
            logger.warning(reason)
            return FlakinessResult(is_flaky=False, reason=reason)

        # Step 2: Wait for build to complete
        build_details = self.client.poll_pipeline_details(
            [build_run],
            timeout=self.poll_timeout,
            check_interval=self.poll_interval,
        )
        build_detail = build_details.get(build_run.commit, {})
        build_is_bad = build_detail.get("is_bad")

        if build_is_bad is None or build_is_bad:
            reason = (
                f"Image build failed or timed out "
                f"(run_id={build_run.run_id}, result={build_detail.get('result')}) "
                f"— cannot determine flakiness, proceeding with bisect."
            )
            logger.warning(reason)
            return FlakinessResult(
                is_flaky=False,
                reason=reason,
                build_run_id=build_run.run_id,
            )

        logger.info("Image build succeeded (run_id=%d), triggering tests",
                    build_run.run_id)

        # Step 3: Trigger N test pipelines with the fresh build
        runs = self._trigger_test_runs(
            branch=branch,
            test_scripts=test_scripts,
            kvm_build_id=str(build_run.run_id),
            mgmt_commit_hash=None,
        )

        if not runs:
            return FlakinessResult(
                is_flaky=False,
                reason="Failed to trigger test pipelines after image build — "
                       "proceeding with bisect.",
                build_run_id=build_run.run_id,
            )

        result = self._poll_and_evaluate(runs)
        result.build_run_id = build_run.run_id
        return result

    def _trigger_latest_build(self, branch: str) -> PipelineRunParameters:
        """Trigger a VS image build from the latest commit on branch."""
        params = BuildPipelineParameters(
            SUBMODULE="sonic-buildimage",
            COMMIT_ID=None,  # None = use HEAD of the branch
        )
        # Use "HEAD" as the commit identifier for trigger_pipeline
        # The payload won't pin a specific "version" since COMMIT_ID is None,
        # so ADO uses the branch HEAD.
        run = trigger_pipeline(
            self.client, branch, "HEAD", "build",
            self.build_pipeline_id, params,
        )
        logger.info("Triggered image build: run_id=%d, url=%s",
                    run.run_id, run.run_url)
        return run

    def _trigger_test_runs(
        self,
        branch: str,
        test_scripts: dict,
        kvm_build_id: Optional[str],
        mgmt_commit_hash: Optional[str],
    ) -> list[PipelineRunParameters]:
        """Trigger N parallel test pipeline runs."""
        runs = []

        def _trigger_one(run_idx: int) -> PipelineRunParameters:
            params = TestPipelineParameters(
                BUILD_REASON=BUILD_REASON,
                BUILD_BRANCH=branch,
                TEST_PLAN_NUM="1",  # 1 test plan per run
                TEST_PLAN_STOP_ON_FAILURE="True",
                RETRY_TIMES=DEFAULT_RETRY_TIMES,
                MGMT_COMMIT_HASH=mgmt_commit_hash,
                IMPACT_AREA_INFO=test_scripts,
                KVM_BUILD_ID=kvm_build_id,
            )
            commit_label = f"HEAD_flakiness_run{run_idx + 1}"
            return trigger_pipeline(
                self.client, branch, commit_label, "test",
                self.test_pipeline_id, params,
            )

        with ThreadPoolExecutor(max_workers=self.num_runs) as executor:
            futures = {
                executor.submit(_trigger_one, i): i
                for i in range(self.num_runs)
            }
            for future in as_completed(futures):
                run_idx = futures[future]
                try:
                    run = future.result()
                    runs.append(run)
                    logger.info("Flakiness test run %d triggered: "
                                "run_id=%d", run_idx + 1, run.run_id)
                except Exception as e:
                    logger.error("Failed to trigger flakiness run %d: %s",
                                 run_idx + 1, e)

        return runs

    def _poll_and_evaluate(
        self, runs: list[PipelineRunParameters]
    ) -> FlakinessResult:
        """Poll all test runs and evaluate flakiness."""
        details = self.client.poll_pipeline_details(
            runs,
            timeout=self.poll_timeout,
            check_interval=self.poll_interval,
        )

        passed = 0
        failed = 0
        errors = 0
        run_ids = []

        for run in runs:
            detail = details.get(run.commit, {})
            is_bad = detail.get("is_bad")
            run_id = detail.get("run_id", run.run_id)
            run_ids.append(run_id)

            if is_bad is False:
                passed += 1
            elif is_bad is True:
                failed += 1
            else:
                errors += 1

        total = len(runs)
        is_flaky = passed > 0
        is_inconclusive = failed == 0 and errors > 0

        if is_flaky:
            reason = (
                f"FLAKY: {passed}/{total} runs passed with latest code. "
                f"Test is not a reliable regression indicator — "
                f"skipping binary search."
            )
        elif is_inconclusive:
            reason = (
                f"INCONCLUSIVE: 0/{total} runs passed, all resulted in errors "
                f"(errors={errors}). Cannot determine flakiness — "
                f"proceeding with binary search."
            )
        else:
            reason = (
                f"CONSISTENT FAILURE: 0/{total} runs passed with latest code "
                f"(failed={failed}, errors={errors}). "
                f"Failure is reproducible — proceeding with binary search."
            )

        logger.info(reason)

        return FlakinessResult(
            is_flaky=is_flaky,
            total_runs=total,
            passed_runs=passed,
            failed_runs=failed,
            error_runs=errors,
            pipeline_run_ids=run_ids,
            reason=reason,
            details={
                "runs": [
                    {
                        "commit_label": run.commit,
                        "run_id": details.get(run.commit, {}).get("run_id", run.run_id),
                        "run_url": details.get(run.commit, {}).get("run_url", run.run_url),
                        "is_bad": details.get(run.commit, {}).get("is_bad"),
                        "status": details.get(run.commit, {}).get("status"),
                        "result": details.get(run.commit, {}).get("result"),
                    }
                    for run in runs
                ],
            },
        )
