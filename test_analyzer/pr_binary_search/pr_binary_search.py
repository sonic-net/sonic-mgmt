import json
import os
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pipeline_triggers import AzureDevOpsClient, trigger_pipeline
from schemas import TestPipelineParameters, BuildPipelineParameters
from binary_plan import DynamicParallelBisect


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
MGMT_REPO = "sonic-net/sonic-mgmt"


def execute_binary_search(client: AzureDevOpsClient, result_json: dict, max_parallel: int,
                          test_pipeline_id: int, build_cache: dict = None):
    repo = result_json['repo']
    branch = result_json['branch']
    test_scripts = result_json['test_scripts']
    commits = result_json['commits']
    commit_ids = [commit['sha'] for commit in commits]

    logger.info(f"Starting binary search for {repo} with {len(commit_ids)} commits")
    searcher = DynamicParallelBisect(commit_ids, max_parallel=max_parallel)

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
                    continue

                if commit_build.get("is_bad") is True:
                    logger.info(f"Skipping tests for {commit} due to failed build run={run_id}")
                    round_results[commit] = True
                    continue
                if commit_build.get("is_bad") is None:
                    logger.warning(f"Skipping tests for {commit} due to unknown build result run={run_id}")
                    round_results[commit] = None
                    continue

            params = TestPipelineParameters(
                BUILD_REASON=BUILD_REASON,
                BUILD_BRANCH=branch,
                TEST_PLAN_NUM=DEFAULT_PARALLEL_TESTS,
                TEST_PLAN_STOP_ON_FAILURE="True",
                RETRY_TIMES=DEFAULT_RETRY_TIMES,
                MGMT_COMMIT_HASH=commit,
                IMPACT_AREA_INFO=test_scripts,
            )
            run = trigger_pipeline(client, branch, commit, "test", test_pipeline_id, params)
            test_runs.append(run)

        # Poll test_runs and update searcher
        test_results = client.poll_pipeline_results(test_runs)
        for commit, is_bad in test_results.items():
            # Only set test results if not already conclusively set by build stage
            if commit not in round_results or round_results[commit] is None:
                round_results[commit] = is_bad
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
        'search_completed': search_status['finished']
    }


def parse_failure_info(failure_info_file):
    with open(failure_info_file, "r") as f:
        records = json.load(f)

    if not isinstance(records, list):
        logger.error(f"Invalid failure info format in {failure_info_file}: expecting list")
        return []

    parsed = []
    skipped_issue_close = 0
    skipped_no_commits = 0
    skipped_invalid = 0

    for item in records:
        # Legacy format (already binary-search ready)
        if all(k in item for k in ("repo", "branch", "test_scripts", "commits")):
            if not item.get("commits"):
                skipped_no_commits += 1
                continue
            parsed.append(item)
            continue

        # New unified format (Kusto schema)
        if "SourceRepo" in item and "Branch" in item:
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
            })
            continue

        skipped_invalid += 1

    logger.info(
        f"Parsed failure entries from {failure_info_file}: selected={len(parsed)}, "
        f"skipped_issue_close={skipped_issue_close}, skipped_no_commits={skipped_no_commits}, "
        f"skipped_invalid={skipped_invalid}"
    )
    return parsed


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


def process_failure_entry(
    client: AzureDevOpsClient,
    result_json: dict,
    entry_key: str,
    max_parallel: int,
    test_pipeline_id: int,
    build_pipeline_id: int,
    build_queue_parallel: int,
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

    result = execute_binary_search(
        client=client,
        result_json=result_json,
        max_parallel=max_parallel,
        test_pipeline_id=test_pipeline_id,
        build_cache=build_map,
    )
    return entry_key, result, build_map


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--failure_info_file", required=True)
    parser.add_argument("--max_parallel", type=int, default=5)
    parser.add_argument("--build_queue_parallel", type=int, default=10)
    parser.add_argument("--build_map_output_file", type=str, default="build_commit_map.json")
    parser.add_argument("--no_prebuild_buildimage", action="store_true")
    args = parser.parse_args()

    failure_info = parse_failure_info(args.failure_info_file)
    if not failure_info:
        logger.error("No failure info found")
        return
    if not MSSONIC_TOKEN:
        logger.error("MSSONIC_TOKEN is empty, cannot trigger Azure DevOps pipelines.")
        return

    client = AzureDevOpsClient(BASE_URL, ORGANIZATION, PROJECT, token=MSSONIC_TOKEN)

    has_buildimage_targets = any(item.get("repo") != MGMT_REPO for item in failure_info)
    if args.no_prebuild_buildimage and has_buildimage_targets:
        logger.error("Buildimage targets detected but prebuild is disabled. "
                     "Use prebuild mode so all VS images are built once before binary search.")
        return

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


if __name__ == "__main__":
    main()
