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


def execute_binary_search(client: AzureDevOpsClient, result_json: dict, max_parallel: int,
                          test_pipeline_id: int, build_pipeline_id: int):
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

        # Build pipelines for non-mgmt repos
        build_results = {}
        build_runs = []
        if repo != "sonic-net/sonic-mgmt":
            for commit in test_commits:
                params = BuildPipelineParameters(
                    SUBMODULE=repo.split("/")[-1],
                    COMMIT_ID=commit,
                )
                run = trigger_pipeline(client, branch, commit, "build", build_pipeline_id, params)
                build_runs.append(run)

            build_results = client.poll_pipeline_results(build_runs)
            for commit, is_bad in build_results.items():
                logger.info(f"Build result for {commit}: {'Failed' if is_bad else 'Succeeded'}")

        # Test pipelines
        test_runs = []
        for commit in test_commits:
            # Skip bad builds
            if repo != "sonic-net/sonic-mgmt" and build_results.get(commit) is True:
                logger.info(f"Skipping tests for {commit} due to failed build")
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

        round_results = {}
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
        return json.load(f)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--failure_info_file", required=True)
    parser.add_argument("--max_parallel", type=int, default=5)
    args = parser.parse_args()

    failure_info = parse_failure_info(args.failure_info_file)
    if not failure_info:
        logger.error("No failure info found")
        return

    client = AzureDevOpsClient(BASE_URL, ORGANIZATION, PROJECT, token=MSSONIC_TOKEN)

    # Execute binary search in parallel
    results = {}
    max_workers = len(failure_info)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_repo = {
            executor.submit(
                execute_binary_search,
                client,
                result_json,
                args.max_parallel,
                test_pipeline_id=PRE_DEFINED_PR_TEST_PIPELINE_ID,
                build_pipeline_id=BUILD_VS_IMAGE_PIPELINE_ID,
            ): result_json
            for result_json in failure_info
        }

        for future in as_completed(future_to_repo):
            repo = future_to_repo[future]
            try:
                results[repo] = future.result()
            except Exception as e:
                logger.error(f"{repo} binary search failed: {e}")
                results[repo] = None

    logger.info("Final Results:")
    for repo, res in results.items():
        logger.info(f"{repo}: {res}")


if __name__ == "__main__":
    main()
