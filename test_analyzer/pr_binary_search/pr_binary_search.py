import json
import os
import logging
import argparse
import uuid
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pipeline_triggers import AzureDevOpsClient, trigger_pipeline
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from azure.kusto.data.exceptions import KustoServiceError
from config import (
    ALLOWED_BRANCHES,
    DEFAULT_FAILURE_INFO_FILE,
    get_failure_info_table,
    KUSTO_DATABASE,
    KUSTO_FAILURE_TABLE,
    KUSTO_LOG_MAPPING,
    KUSTO_LOG_TABLE,
    KUSTO_RESULT_MAPPING,
    KUSTO_RESULT_TABLE,
    KUSTO_TESTPLAN_MAP_MAPPING,
    KUSTO_TESTPLAN_MAP_TABLE,
    MGMT_REPO,
)
from schemas import TestPipelineParameters, BuildPipelineParameters
from binary_plan import DynamicParallelBisect
from kusto_uploader import ingest_records_from_env


logging.basicConfig(level=logging.INFO, format='[%(threadName)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

MSSONIC_TOKEN = os.getenv("MSSONIC_TOKEN")
BUILD_REASON = "BinarySearch"
# Default parameters used across pipelines
DEFAULT_PARALLEL_TESTS = "3"
DEFAULT_RETRY_TIMES = "2"

# Azure DevOps pipeline IDs
BUILD_VS_IMAGE_PIPELINE_ID = 3332
PRE_DEFINED_PR_TEST_PIPELINE_ID = 3320

# Azure DevOps API endpoints (Builds API)
BASE_URL = "https://dev.azure.com/"
ORGANIZATION = "mssonic"
PROJECT = "build"


def parse_bool_arg(value):
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"Invalid boolean value: {value}")


def isoformat_utc(dtobj):
    return dtobj.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_failure_join_key(metadata):
    return "|".join([
        metadata.get("repo", ""),
        metadata.get("branch", ""),
        metadata.get("trigger_type", ""),
        metadata.get("checker", ""),
        metadata.get("file_path", ""),
        metadata.get("module_path", ""),
        metadata.get("testcase", ""),
    ])


def execute_binary_search(client: AzureDevOpsClient, result_json: dict, max_parallel: int,
                          test_pipeline_id: int, build_cache: dict = None,
                          search_run_id: str = None):
    repo = result_json['repo']
    branch = result_json['branch']
    test_scripts = result_json['test_scripts']
    commits = result_json['commits']
    commit_ids = [commit['sha'] for commit in commits]

    logger.info(f"Starting binary search for {repo} with {len(commit_ids)} commits")
    searcher = DynamicParallelBisect(commit_ids, max_parallel=max_parallel)
    execution_records = []
    test_plan_records = []
    metadata_base = {
        "analyzer_run_id": result_json.get("analyzer_run_id"),
        "repo": repo,
        "branch": branch,
        "trigger_type": result_json.get("trigger_type"),
        "checker": result_json.get("checker"),
        "file_path": result_json.get("file_path"),
        "module_path": result_json.get("module_path"),
        "testcase": result_json.get("testcase"),
    }
    failure_join_key = build_failure_join_key(metadata_base)

    round_number = 0
    while True:
        round_number += 1
        test_plan = searcher.get_next_test_commits()
        if test_plan is None:
            logger.info(f"Binary search completed for {repo}")
            break

        test_commits = test_plan['tests']
        logger.info(f"Round {round_number} testing commits: {test_commits}")

        round_results = {}

        # Test pipelines
        test_runs = []
        for commit in test_commits:
            if repo != MGMT_REPO:
                commit_build = (build_cache or {}).get(commit)
                run_id = commit_build.get("run_id") if commit_build else None
                if not commit_build:
                    logger.error(f"No prebuild mapping for {commit}, cannot run buildimage binary search safely")
                    round_results[commit] = None
                    execution_records.append({
                        "SearchRunId": search_run_id,
                        "AnalyzerRunId": result_json.get("analyzer_run_id"),
                        "FailureJoinKey": failure_join_key,
                        "TriggerType": result_json.get("trigger_type"),
                        "SourceRepo": repo,
                        "Branch": branch,
                        "CheckerType": result_json.get("checker"),
                        "FilePath": result_json.get("file_path"),
                        "ModulePath": result_json.get("module_path"),
                        "TestCase": result_json.get("testcase"),
                        "RoundNumber": round_number,
                        "CommitSha": commit,
                        "Stage": "test",
                        "Verdict": "missing_prebuild_mapping",
                        "IsBad": None,
                        "PipelineDefinitionId": test_pipeline_id,
                        "PipelineRunId": None,
                        "PipelineUrl": None,
                        "Status": "skipped",
                        "Result": "missing_prebuild_mapping",
                        "BuildReason": BUILD_REASON,
                        "ImpactAreaInfo": test_scripts,
                        "RawRecord": {"build_cache": commit_build},
                        "UploadTime": isoformat_utc(datetime.now(tz=timezone.utc)),
                    })
                    continue

                if commit_build.get("is_bad") is True:
                    logger.info(f"Skipping tests for {commit} due to failed build run={run_id}")
                    round_results[commit] = True
                    execution_records.append({
                        "SearchRunId": search_run_id,
                        "AnalyzerRunId": result_json.get("analyzer_run_id"),
                        "FailureJoinKey": failure_join_key,
                        "TriggerType": result_json.get("trigger_type"),
                        "SourceRepo": repo,
                        "Branch": branch,
                        "CheckerType": result_json.get("checker"),
                        "FilePath": result_json.get("file_path"),
                        "ModulePath": result_json.get("module_path"),
                        "TestCase": result_json.get("testcase"),
                        "RoundNumber": round_number,
                        "CommitSha": commit,
                        "Stage": "test",
                        "Verdict": "build_failed_skip_test",
                        "IsBad": True,
                        "PipelineDefinitionId": test_pipeline_id,
                        "PipelineRunId": str(run_id) if run_id is not None else None,
                        "PipelineUrl": commit_build.get("run_url"),
                        "Status": commit_build.get("status"),
                        "Result": commit_build.get("result"),
                        "BuildReason": BUILD_REASON,
                        "ImpactAreaInfo": test_scripts,
                        "RawRecord": {"build_cache": commit_build},
                        "UploadTime": isoformat_utc(datetime.now(tz=timezone.utc)),
                    })
                    continue
                if commit_build.get("is_bad") is None:
                    logger.warning(f"Skipping tests for {commit} due to unknown build result run={run_id}")
                    round_results[commit] = None
                    execution_records.append({
                        "SearchRunId": search_run_id,
                        "AnalyzerRunId": result_json.get("analyzer_run_id"),
                        "FailureJoinKey": failure_join_key,
                        "TriggerType": result_json.get("trigger_type"),
                        "SourceRepo": repo,
                        "Branch": branch,
                        "CheckerType": result_json.get("checker"),
                        "FilePath": result_json.get("file_path"),
                        "ModulePath": result_json.get("module_path"),
                        "TestCase": result_json.get("testcase"),
                        "RoundNumber": round_number,
                        "CommitSha": commit,
                        "Stage": "test",
                        "Verdict": "unknown_build_skip_test",
                        "IsBad": None,
                        "PipelineDefinitionId": test_pipeline_id,
                        "PipelineRunId": str(run_id) if run_id is not None else None,
                        "PipelineUrl": commit_build.get("run_url"),
                        "Status": commit_build.get("status"),
                        "Result": commit_build.get("result"),
                        "BuildReason": BUILD_REASON,
                        "ImpactAreaInfo": test_scripts,
                        "RawRecord": {"build_cache": commit_build},
                        "UploadTime": isoformat_utc(datetime.now(tz=timezone.utc)),
                    })
                    continue

            if repo != MGMT_REPO:
                # sonic-buildimage binary search: use the pre-built VS image identified
                # by its build run ID.  MGMT_COMMIT_HASH is left unset so the test
                # pipeline checks out the HEAD of sonic-mgmt (test scripts stay fixed
                # across rounds; only the image changes).
                params = TestPipelineParameters(
                    BUILD_REASON=BUILD_REASON,
                    BUILD_BRANCH=branch,
                    TEST_PLAN_NUM=DEFAULT_PARALLEL_TESTS,
                    TEST_PLAN_STOP_ON_FAILURE="True",
                    RETRY_TIMES=DEFAULT_RETRY_TIMES,
                    IMPACT_AREA_INFO=test_scripts,
                    KVM_BUILD_ID=str(commit_build["run_id"]),
                )
            else:
                # sonic-mgmt binary search: pin the mgmt commit being tested.
                params = TestPipelineParameters(
                    BUILD_REASON=BUILD_REASON,
                    BUILD_BRANCH=branch,
                    TEST_PLAN_NUM=DEFAULT_PARALLEL_TESTS,
                    TEST_PLAN_STOP_ON_FAILURE="True",
                    RETRY_TIMES=DEFAULT_RETRY_TIMES,
                    MGMT_COMMIT_HASH=commit,
                    IMPACT_AREA_INFO=test_scripts,
                )
            try:
                run = trigger_pipeline(client, branch, commit, "test", test_pipeline_id, params)
                test_runs.append(run)
                execution_records.append({
                    "SearchRunId": search_run_id,
                    "AnalyzerRunId": result_json.get("analyzer_run_id"),
                    "FailureJoinKey": failure_join_key,
                    "TriggerType": result_json.get("trigger_type"),
                    "SourceRepo": repo,
                    "Branch": branch,
                    "CheckerType": result_json.get("checker"),
                    "FilePath": result_json.get("file_path"),
                    "ModulePath": result_json.get("module_path"),
                    "TestCase": result_json.get("testcase"),
                    "RoundNumber": round_number,
                    "CommitSha": commit,
                    "Stage": "test",
                    "Verdict": "queued",
                    "IsBad": None,
                    "PipelineDefinitionId": test_pipeline_id,
                    "PipelineRunId": str(run.run_id),
                    "PipelineUrl": run.run_url,
                    "Status": "queued",
                    "Result": None,
                    "BuildReason": BUILD_REASON,
                    "ImpactAreaInfo": test_scripts,
                    "RawRecord": {"payload": params.to_payload()},
                    "UploadTime": isoformat_utc(datetime.now(tz=timezone.utc)),
                })
            except Exception as trigger_err:
                logger.error(f"Failed to trigger test pipeline for commit {commit}: {trigger_err}")
                round_results[commit] = None
                execution_records.append({
                    "SearchRunId": search_run_id,
                    "AnalyzerRunId": result_json.get("analyzer_run_id"),
                    "FailureJoinKey": failure_join_key,
                    "TriggerType": result_json.get("trigger_type"),
                    "SourceRepo": repo,
                    "Branch": branch,
                    "CheckerType": result_json.get("checker"),
                    "FilePath": result_json.get("file_path"),
                    "ModulePath": result_json.get("module_path"),
                    "TestCase": result_json.get("testcase"),
                    "RoundNumber": round_number,
                    "CommitSha": commit,
                    "Stage": "test",
                    "Verdict": "trigger_error",
                    "IsBad": None,
                    "PipelineDefinitionId": test_pipeline_id,
                    "PipelineRunId": None,
                    "PipelineUrl": None,
                    "Status": "trigger_error",
                    "Result": str(trigger_err),
                    "BuildReason": BUILD_REASON,
                    "ImpactAreaInfo": test_scripts,
                    "RawRecord": {"error": str(trigger_err), "payload": params.to_payload()},
                    "UploadTime": isoformat_utc(datetime.now(tz=timezone.utc)),
                })

        test_details = client.poll_pipeline_details(test_runs)
        for run in test_runs:
            detail = test_details.get(run.commit)
            if detail and detail.get("run_id"):
                for test_plan_id in client.extract_test_plan_ids(detail["run_id"]):
                    test_plan_records.append({
                        "SearchRunId": search_run_id,
                        "FailureJoinKey": failure_join_key,
                        "PipelineRunId": str(detail["run_id"]),
                        "RoundNumber": round_number,
                        "CommitSha": run.commit,
                        "TestPlanId": test_plan_id,
                        "UploadTime": isoformat_utc(datetime.now(tz=timezone.utc)),
                    })

        for commit, detail in test_details.items():
            is_bad = detail.get("is_bad")
            # Only set test results if not already conclusively set by build stage
            if commit not in round_results or round_results[commit] is None:
                round_results[commit] = is_bad
            execution_records.append({
                "SearchRunId": search_run_id,
                "AnalyzerRunId": result_json.get("analyzer_run_id"),
                "FailureJoinKey": failure_join_key,
                "TriggerType": result_json.get("trigger_type"),
                "SourceRepo": repo,
                "Branch": branch,
                "CheckerType": result_json.get("checker"),
                "FilePath": result_json.get("file_path"),
                "ModulePath": result_json.get("module_path"),
                "TestCase": result_json.get("testcase"),
                "RoundNumber": round_number,
                "CommitSha": commit,
                "Stage": "test",
                "Verdict": "completed",
                "IsBad": is_bad,
                "PipelineDefinitionId": test_pipeline_id,
                "PipelineRunId": str(detail.get("run_id")) if detail.get("run_id") is not None else None,
                "PipelineUrl": detail.get("run_url"),
                "Status": detail.get("status"),
                "Result": detail.get("result"),
                "BuildReason": BUILD_REASON,
                "ImpactAreaInfo": test_scripts,
                "RawRecord": detail,
                "UploadTime": isoformat_utc(datetime.now(tz=timezone.utc)),
            })
        valid_results = {k: v for k, v in round_results.items() if v is not None}
        if not valid_results:
            logger.error(f"No valid results for round {round_number} in {repo}")
            break
        status = searcher.submit_test_results(valid_results)
        logger.info(f"Round {round_number} completed for {repo}")
        logger.info(f"Eliminated commits: {status['eliminated_commits']}")

        if status['finished']:
            if status['result']:
                logger.info(f"Found bad commit for {repo}: {status['result']}")
            else:
                logger.info(f"No bad commit found for {repo}")
            break

    # Return final result
    final_result, range_info = searcher.get_result()
    search_status = searcher.get_search_status()

    return {
        'repo': repo,
        'bad_commit': final_result,
        'total_rounds': search_status['current_round'],
        'final_range': range_info,
        'metadata': result_json,
        'search_completed': search_status['finished'],
        'execution_records': execution_records,
        'test_plan_records': test_plan_records,
    }


def fetch_failure_info_from_kusto(kusto_client, lookback_hours=48, table=None):
    """Query a PRBinarySearchFailureInfo-schema table for recent records to drive binary search."""
    if table is None or not str(table).strip():
        table = KUSTO_FAILURE_TABLE
    query = f"""
        {table}
        | where UploadTime > ago({lookback_hours}h)
        | project AnalyzerRunId, SourceRepo, Branch, TriggerType, CheckerType,
                FilePath, ModulePath, TestCase, Commits, LikelyIssueClose, RawFailureInfo
        """
    try:
        rows = kusto_client.execute_query(KUSTO_DATABASE, query).primary_results[0].to_dict()["data"]
    except KustoServiceError as exc:
        logger.error(f"Kusto query for failure info failed: {exc}")
        return []
    records = []
    for row in rows:
        record = dict(row)
        raw = record.get("RawFailureInfo")
        if isinstance(raw, str):
            try:
                record["RawFailureInfo"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                pass
        records.append(record)
    logger.info(f"Fetched {len(records)} failure info records from Kusto (lookback={lookback_hours}h)")
    return records


def parse_failure_info_records(records, allowed_branches=None):
    if not isinstance(records, list):
        logger.error("Invalid failure info format: expecting list")
        return []

    parsed = []
    skipped_issue_close = 0
    skipped_no_commits = 0
    skipped_invalid = 0

    for item in records:
        # Legacy format (already binary-search ready)
        if all(k in item for k in ("repo", "branch", "test_scripts", "commits")):
            if allowed_branches is not None and item.get("branch") not in allowed_branches:
                skipped_invalid += 1
                continue
            if not item.get("commits"):
                skipped_no_commits += 1
                continue
            parsed.append(item)
            continue

        # New unified format (Kusto schema)
        if "SourceRepo" in item and "Branch" in item:
            if allowed_branches is not None and item.get("Branch") not in allowed_branches:
                skipped_invalid += 1
                continue
            if item.get("LikelyIssueClose") is True:
                skipped_issue_close += 1
                continue

            commits = item.get("Commits") or []
            if not commits:
                skipped_no_commits += 1
                continue

            raw = item.get("RawFailureInfo") or {}
            test_scripts = raw.get("test_scripts")
            if not test_scripts:
                checker = item.get("CheckerType")
                file_path = item.get("FilePath")
                if checker and file_path:
                    test_scripts = {checker: [file_path]}
                else:
                    skipped_invalid += 1
                    continue

            parsed.append({
                "repo": item.get("SourceRepo"),
                "branch": item.get("Branch"),
                "test_scripts": test_scripts,
                "commits": commits,
                "analyzer_run_id": item.get("AnalyzerRunId"),
                "trigger_type": item.get("TriggerType"),
                "checker": item.get("CheckerType"),
                "file_path": item.get("FilePath"),
                "module_path": item.get("ModulePath"),
                "testcase": item.get("TestCase"),
                "likely_issue_close": item.get("LikelyIssueClose"),
                "issue_close_analysis": raw.get("issue_close_analysis", {}),
            })
            continue

        skipped_invalid += 1

    logger.info(
        f"Parsed failure entries: selected={len(parsed)}, "
        f"skipped_issue_close={skipped_issue_close}, skipped_no_commits={skipped_no_commits}, "
        f"skipped_invalid={skipped_invalid}"
    )
    return parsed


def parse_failure_info(failure_info_file, allowed_branches=None):
    with open(failure_info_file, "r") as f:
        records = json.load(f)
    return parse_failure_info_records(records, allowed_branches=allowed_branches)


def _trigger_build_for_commit(client, repo, branch, build_pipeline_id, commit):
    params = BuildPipelineParameters(
        SUBMODULE=repo.split("/")[-1],
        COMMIT_ID=commit,
    )
    run = trigger_pipeline(client, branch, commit, "build", build_pipeline_id, params)
    return run


def prebuild_commits_for_repo(
    client: AzureDevOpsClient,
    repo: str,
    branch: str,
    commit_ids: list,
    build_pipeline_id: int,
    build_queue_parallel: int,
):
    unique_commits = list(dict.fromkeys(commit_ids))
    logger.info(f"Prebuild start for {repo}@{branch}, total commits={len(unique_commits)}")

    build_runs = []
    build_map = {}

    with ThreadPoolExecutor(max_workers=max(1, min(build_queue_parallel, len(unique_commits)))) as executor:
        futures = {
            executor.submit(_trigger_build_for_commit, client, repo, branch, build_pipeline_id, commit): commit
            for commit in unique_commits
        }
        for future in as_completed(futures):
            commit = futures[future]
            try:
                build_runs.append(future.result())
            except Exception as e:
                logger.error(f"Queue build failed for {commit}: {e}")
                build_map[commit] = {
                    "is_bad": None,
                    "run_id": None,
                    "run_url": None,
                    "status": "queue_error",
                    "result": str(e),
                }

    polled_details = client.poll_pipeline_details(build_runs)
    build_map.update(polled_details)
    logger.info(f"Prebuild done for {repo}@{branch}, completed builds={len(polled_details)}")
    return build_map


def write_build_map(build_cache, output_file):
    if not output_file:
        return
    serializable = {}
    for key, commit_map in build_cache.items():
        if isinstance(key, tuple) and len(key) == 2:
            repo, branch = key
            serializable[f"{repo}@{branch}"] = commit_map
        else:
            serializable[str(key)] = commit_map
    with open(output_file, "w") as f:
        json.dump(serializable, f, indent=2)
    logger.info(f"Build commit mapping written to {output_file}")


def build_summary_records(results, search_run_id):
    upload_time = isoformat_utc(datetime.now(tz=timezone.utc))
    records = []

    for result in results.values():
        if not result:
            continue

        metadata = result.get("metadata") or {}
        issue_close_analysis = metadata.get("issue_close_analysis") or {}
        confirmed_issue = next(
            (issue for issue in issue_close_analysis.get("issues", []) if issue.get("closed_in_window")),
            None,
        )
        root_cause_type = (
            "issue_close"
            if confirmed_issue
            else ("bad_commit" if result.get("bad_commit") else "unknown")
        )
        root_cause_value = (
            confirmed_issue.get("url") if confirmed_issue else result.get("bad_commit")
        )
        issue_url = confirmed_issue.get("url", "") if confirmed_issue else ""
        issue_repo = (
            issue_url.split("/issues/")[0].replace("https://github.com/", "")
            if confirmed_issue
            else None
        )
        issue_number = issue_url.rsplit("/", 1)[-1] if confirmed_issue else None
        final_range = result.get("final_range")
        tested_pipeline_run_ids = sorted(
            {
                record.get("PipelineRunId")
                for record in result.get("execution_records", [])
                if record.get("PipelineRunId")
            }
        )
        tested_test_plan_ids = sorted(
            {
                record.get("TestPlanId")
                for record in result.get("test_plan_records", [])
                if record.get("TestPlanId")
            }
        )

        records.append({
            "SearchRunId": search_run_id,
            "AnalyzerRunId": metadata.get("analyzer_run_id"),
            "FailureJoinKey": build_failure_join_key(metadata),
            "TriggerType": metadata.get("trigger_type"),
            "SourceRepo": metadata.get("repo"),
            "Branch": metadata.get("branch"),
            "CheckerType": metadata.get("checker"),
            "FilePath": metadata.get("file_path"),
            "ModulePath": metadata.get("module_path"),
            "TestCase": metadata.get("testcase"),
            "LikelyIssueClose": bool(metadata.get("likely_issue_close")),
            "RootCauseType": root_cause_type,
            "RootCauseValue": root_cause_value,
            "IssueRepo": issue_repo,
            "IssueNumber": issue_number,
            "IssueClosedAt": confirmed_issue.get("closed_at") if confirmed_issue else None,
            "BadCommit": result.get("bad_commit"),
            "TotalRounds": result.get("total_rounds"),
            "SearchCompleted": result.get("search_completed"),
            "FinalRange": list(final_range) if final_range is not None else None,
            "TestedPipelineRunIds": tested_pipeline_run_ids,
            "TestedTestPlanIds": tested_test_plan_ids,
            "RawSummary": result,
            "UploadTime": upload_time,
        })

    return records


def process_failure_entry(
    client: AzureDevOpsClient,
    result_json: dict,
    entry_key: str,
    max_parallel: int,
    test_pipeline_id: int,
    build_pipeline_id: int,
    build_queue_parallel: int,
    search_run_id: str,
):
    repo = result_json.get("repo")
    branch = result_json.get("branch")
    build_map = None

    if repo != MGMT_REPO:
        commit_ids = [commit.get("sha") for commit in result_json.get("commits", []) if commit.get("sha")]
        build_map = prebuild_commits_for_repo(
            client=client,
            repo=repo,
            branch=branch,
            commit_ids=commit_ids,
            build_pipeline_id=build_pipeline_id,
            build_queue_parallel=build_queue_parallel,
        )

    execution_records = []
    if build_map is not None:
        failure_join_key = build_failure_join_key(result_json)
        for commit, detail in build_map.items():
            run_id = detail.get("run_id")
            status = detail.get("status")
            verdict = (
                "completed"
                if status not in {"queue_error", "timeout", "error"}
                else status
            )
            execution_records.append({
                "SearchRunId": search_run_id,
                "AnalyzerRunId": result_json.get("analyzer_run_id"),
                "FailureJoinKey": failure_join_key,
                "TriggerType": result_json.get("trigger_type"),
                "SourceRepo": repo,
                "Branch": branch,
                "CheckerType": result_json.get("checker"),
                "FilePath": result_json.get("file_path"),
                "ModulePath": result_json.get("module_path"),
                "TestCase": result_json.get("testcase"),
                "RoundNumber": 0,
                "CommitSha": commit,
                "Stage": "build",
                "Verdict": verdict,
                "IsBad": detail.get("is_bad"),
                "PipelineDefinitionId": build_pipeline_id,
                "PipelineRunId": str(run_id) if run_id is not None else None,
                "PipelineUrl": detail.get("run_url"),
                "Status": status,
                "Result": detail.get("result"),
                "BuildReason": BUILD_REASON,
                "ImpactAreaInfo": result_json.get("test_scripts"),
                "RawRecord": detail,
                "UploadTime": isoformat_utc(datetime.now(tz=timezone.utc)),
            })

    try:
        result = execute_binary_search(
            client=client,
            result_json=result_json,
            max_parallel=max_parallel,
            test_pipeline_id=test_pipeline_id,
            build_cache=build_map,
            search_run_id=search_run_id,
        )
    except Exception as search_err:
        # An unhandled error inside the binary search loop (e.g. an unexpected
        # API failure) must not swallow the build-stage and any partial test-
        # stage records already collected above.  Return a minimal result so
        # process_failure_entry always completes and Kusto upload still runs.
        logger.error(f"execute_binary_search raised an unexpected error for {repo}@{branch}: {search_err}")
        result = {
            "repo": repo,
            "bad_commit": None,
            "total_rounds": 0,
            "final_range": None,
            "metadata": result_json,
            "search_completed": False,
            "execution_records": [],
            "test_plan_records": [],
        }
    result['execution_records'] = execution_records + result.get('execution_records', [])
    return entry_key, result, build_map


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--failure_info_file", default=DEFAULT_FAILURE_INFO_FILE)
    parser.add_argument("--max_parallel", type=int, default=5)
    parser.add_argument("--build_queue_parallel", type=int, default=10)
    parser.add_argument("--build_map_output_file", type=str, default="build_commit_map.json")
    parser.add_argument("--upload_kusto", type=parse_bool_arg, default=False, help="Upload to Kusto")
    parser.add_argument("--from_kusto", type=parse_bool_arg, default=False,
                        help="Fetch failure info from Kusto instead of a local file")
    parser.add_argument("--kusto_lookback_hours", type=int, default=48,
                        help="Lookback window (hours) when fetching failure info from Kusto")
    parser.add_argument("--USE_AGENCY_FAILURE_INFO", type=parse_bool_arg, default=False,
                        help="Use PRBinarySearchFailureInfoAgency instead of PRBinarySearchFailureInfo")
    args = parser.parse_args()
    search_run_id = str(uuid.uuid4())

    allowed_branches = set(ALLOWED_BRANCHES)
    if args.from_kusto:
        access_token = os.environ.get("ACCESS_TOKEN")
        kusto_ingest_url = os.environ.get("KUSTO_CLUSTER_INGEST_URL")
        if not access_token or not kusto_ingest_url:
            logger.error("ACCESS_TOKEN and KUSTO_CLUSTER_INGEST_URL env vars are required for --from_kusto")
            return
        # Derive query endpoint from ingest URL: strip the "ingest-" prefix
        kusto_query_url = kusto_ingest_url.replace("//ingest-", "//", 1)
        kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(kusto_query_url, access_token)
        kusto_client = KustoClient(kcsb)
        records = fetch_failure_info_from_kusto(
            kusto_client,
            lookback_hours=args.kusto_lookback_hours,
            table=get_failure_info_table(args.USE_AGENCY_FAILURE_INFO),
        )
        failure_info = parse_failure_info_records(records, allowed_branches=allowed_branches)
    else:
        failure_info = parse_failure_info(args.failure_info_file, allowed_branches=allowed_branches)
    if not failure_info:
        logger.error("No failure info found")
        return
    if not MSSONIC_TOKEN:
        logger.error("MSSONIC_TOKEN is empty, cannot trigger Azure DevOps pipelines.")
        return

    client = AzureDevOpsClient(BASE_URL, ORGANIZATION, PROJECT, token=MSSONIC_TOKEN)

    # Execute each failure entry in parallel. Buildimage entries prebuild first, mgmt entries test directly.
    results = {}
    build_maps_by_entry = {}
    max_workers = max(1, len(failure_info))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_repo = {}
        for idx, result_json in enumerate(failure_info):
            repo = result_json.get("repo")
            branch = result_json.get("branch")
            entry_key = f"{repo}@{branch}#{idx}"

            future = executor.submit(
                process_failure_entry,
                client,
                result_json,
                entry_key,
                args.max_parallel,
                PRE_DEFINED_PR_TEST_PIPELINE_ID,
                BUILD_VS_IMAGE_PIPELINE_ID,
                args.build_queue_parallel,
                search_run_id,
            )
            future_to_repo[future] = entry_key

        for future in as_completed(future_to_repo):
            entry_key = future_to_repo[future]
            try:
                finished_entry_key, search_result, build_map = future.result()
                results[finished_entry_key] = search_result
                if build_map is not None:
                    build_maps_by_entry[finished_entry_key] = build_map
            except Exception as e:
                logger.error(f"{entry_key} binary search failed: {e}")
                results[entry_key] = None

    write_build_map(build_maps_by_entry, args.build_map_output_file)

    logger.info("Final Results:")
    for repo, res in results.items():
        logger.info(f"{repo}: {res}")

    if args.upload_kusto:
        all_execution_records = []
        all_test_plan_records = []
        for res in results.values():
            if not res:
                continue
            all_execution_records.extend(res.get("execution_records", []))
            all_test_plan_records.extend(res.get("test_plan_records", []))

        if all_execution_records:
            ingest_records_from_env(
                all_execution_records,
                database=KUSTO_DATABASE,
                table=KUSTO_LOG_TABLE,
                mapping=KUSTO_LOG_MAPPING,
            )
        if all_test_plan_records:
            ingest_records_from_env(
                all_test_plan_records,
                database=KUSTO_DATABASE,
                table=KUSTO_TESTPLAN_MAP_TABLE,
                mapping=KUSTO_TESTPLAN_MAP_MAPPING,
            )
        ingest_records_from_env(
            build_summary_records(results, search_run_id),
            database=KUSTO_DATABASE,
            table=KUSTO_RESULT_TABLE,
            mapping=KUSTO_RESULT_MAPPING,
        )


if __name__ == "__main__":
    main()
