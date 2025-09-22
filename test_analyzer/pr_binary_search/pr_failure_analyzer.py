'''
PR Failure Analyzer
======================================
1. Get PRTest failures with low success rate
2. Get BaselineTest failures with low success rate
3. Remove duplicates between PRTest and BaselineTest failures
4. For each unique failure, get the time range of failures
5. For each unique failure, get the commits merged into the branch between the time range
6. Print the commit information
'''

import os
import sys
import logging
import requests
import argparse
import datetime as dt
from datetime import timezone, timedelta
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)

PR_SUMMARY_TABLE = "PRTestCaseResultSummary"
DATABASE = "SonicTestData"
ingest_cluster = os.environ.get("KUSTO_CLUSTER_INGEST_URL", None)
cluster = ingest_cluster.replace("ingest-", "") if ingest_cluster else None
access_token = os.environ.get("ACCESS_TOKEN", None)
github_api_token = os.environ.get("GIT_API_TOKEN", None)
TOTAL_COUNT_THRESHOLD = os.environ.get("TOTAL_TEST_COUNT_THRESHOLD", 10)
PREVIOUS_SUCCESS_THRESHOLD = os.environ.get("PREVIOUS_SUCCESS_THRESHOLD", 0.7)
PR_LOW_SUCCESS_THRESHOLD = os.environ.get("PR_LOW_SUCCESS_THRESHOLD", 0.5)
BASELINE_LOW_SUCCESS_THRESHOLD = os.environ.get("BASELINE_LOW_SUCCESS_THRESHOLD", 0.5)
QUERY_DAYS_RANGE = os.environ.get("QUERY_DAYS_RANGE", 7)
SUPPORTED_PUBLIC_REPOS = ["sonic-net/sonic-mgmt", "sonic-net/sonic-buildimage"]


def isoformat_kusto(dtobj: dt.datetime) -> str:
    return dtobj.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_github_commits(repo, branch, start_time, end_time):
    """
    Return list of commit SHAs merged into `branch` (if provided) between since and until.
    Falls back to listing commits on the branch with since/until. Requires GITHUB_TOKEN.
    """
    headers = {"Authorization": f"token {github_api_token}", "Accept": "application/vnd.github+json"}
    logger.info(f"Fetching commits for {repo} branch={branch} since={start_time} until={end_time}")
    if not github_api_token:
        logger.warning("No GitHub API token found, skipping commit fetch.")
        return []

    url = f"https://api.github.com/repos/{repo}/commits?sha={branch}"
    params = {
        "since": start_time,
        "until": end_time,
    }
    commits = []
    while url:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code != 200:
            logger.error(f"GitHub API error {response.status_code}: {response.text}")
            break
        data = response.json()
        for item in data:
            commit_sha = item["sha"]
            commit_date = item["commit"]["author"]["date"]
            commits.append({"sha": commit_sha, "date": commit_date})
        # Check for pagination
        if 'next' in response.links:
            url = response.links['next']['url']
            params = None  # already included in the next URL
        else:
            url = None
    return commits


def get_all_commits_info(failure_details):
    """
    Return list of commit SHAs merged into `branch` (if provided) between since and until.
    Falls back to listing commits on the branch with since/until. Requires GITHUB_TOKEN.
    """
    all_commit_info = []
    for detail in failure_details:
        repo = detail["repo"]
        branch = detail["branch"]
        start_time = detail["start_time"]
        end_time = detail["end_time"]
        commits = get_github_commits(repo, branch, start_time, end_time)
        if len(commits) > 0:
            commit_info = {
                "repo": repo,
                "branch": branch,
                "testbed": detail["testbed"],
                "testcase": detail["testcase"],
                "file_path": detail["file_path"],
                "module_path": detail["module_path"],
                "commits": commits
            }
            all_commit_info.append(commit_info)

    return all_commit_info


def get_pr_result_summary(kusto, start, end):
    # time series for baseline tests
    query = f'''
    {PR_SUMMARY_TABLE}
    | where RunDate between (datetime({isoformat_kusto(start)}) .. datetime({isoformat_kusto(end)}))
    | where TotalCount > {TOTAL_COUNT_THRESHOLD}
    | where SourceRepo in ({', '.join(f'"{repo}"' for repo in SUPPORTED_PUBLIC_REPOS)})
    | summarize Success=sum(SuccessCount), Total=sum(TotalCount), Skip=sum(SkipCount), Failure=sum(FailureCount), \
        Error=sum(ErrorCount) by RunDate, SourceRepo, Branch, TestbedName, FilePath, ModulePath, TestCase, TriggerType
    | where Total != Skip
    | project RunDate, TriggerType, SourceRepo, Branch, TestbedName, TestCase, FilePath, ModulePath, \
        Success, Failure, Error, Skip, Total
    | extend SuccessRate = todouble(Success) / todouble(Success + Failure + Error)
    | project TriggerType, SourceRepo, Branch, TestbedName, FilePath, ModulePath, TestCase, SuccessRate, RunDate
    '''
    query_result = kusto.execute_query(DATABASE, query).primary_results[0].to_dict()['data']
    baseline_failures = []
    pr_failures = []

    for row in query_result:
        if row['TriggerType'] == 'BaselineTest' and float(row['SuccessRate']) < BASELINE_LOW_SUCCESS_THRESHOLD:
            baseline_failures.append(row)
        elif row['TriggerType'] == 'PRTest' and float(row['SuccessRate']) < PR_LOW_SUCCESS_THRESHOLD:
            pr_failures.append(row)

    # Check if baseline and pr failures have common entries
    # If so, remove them from pr_failures to avoid duplicate analysis
    pr_keys = {(row['SourceRepo'], row['Branch'], row['TestbedName'], row['ModulePath'], row['TestCase'])
               for row in pr_failures}
    baseline_failures = [row for row in baseline_failures if (
        row['SourceRepo'], row['Branch'], row['TestbedName'], row['ModulePath'], row['TestCase']) not in pr_keys]

    return baseline_failures, pr_failures


def get_failure_details(kusto, failure_details, failures, trigger_type):
    for row in failures:
        query_time_range = f'''
        {PR_SUMMARY_TABLE}
        | where RunDate >= ago(7d)
        | where TriggerType == "{trigger_type}"
        | where SourceRepo == "{row['SourceRepo']}"
        | where Branch == "{row['Branch']}"
        | where TestbedName == "{row['TestbedName']}"
        | where FilePath == "{row['FilePath']}"
        | where ModulePath == "{row['ModulePath']}"
        | where TestCase == "{row['TestCase']}"
        | summarize Success=sum(SuccessCount), Total=sum(TotalCount), Skip=sum(SkipCount), Failure=sum(FailureCount), \
            Error=sum(ErrorCount) by RunDate, SourceRepo, Branch, TestbedName, \
            FilePath, ModulePath, TestCase, TriggerType
        | project RunDate, SourceRepo, Branch, TestbedName, TestCase, FilePath, ModulePath, \
            Success, Failure, Error, Skip, Total
        | where Total != Skip and Total > 0
        | extend SuccessRate = todouble(Success) / todouble(Success + Failure + Error)
        | where SuccessRate < {PREVIOUS_SUCCESS_THRESHOLD}
        | summarize EarliestTime = min(RunDate), LatestTime = max(RunDate)
        '''
        query_time_range = kusto.execute_query(DATABASE, query_time_range).primary_results[0].to_dict()['data']
        if len(query_time_range) == 0:
            logger.info(f"No failure time range found for {row['TestCase']}, skipping.")
            continue
        start_time = query_time_range[0].get('EarliestTime', None)
        end_time = query_time_range[0].get('LatestTime', None)
        if not start_time or not end_time:
            logger.info(f"No valid failure time range found for {row['TestCase']}, skipping.")
            continue
        start_time = start_time - timedelta(days=1)  # 1 day before the first failure
        logger.info(f"Found failure time range for {row['TestCase']}: {start_time} - {end_time}")

        # Use 1 day before the first failing time as start_time to fetch commits
        failure_details.append({
            "repo": row['SourceRepo'],
            "branch": row['Branch'],
            "testbed": row['TestbedName'],
            "testcase": row['TestCase'],
            "file_path": row['FilePath'],
            "module_path": row['ModulePath'],
            "trigger_type": trigger_type,
            "start_time": str(start_time),
            "end_time": str(end_time)
        })

    return failure_details


def remove_duplicates_failures(failure_details):
    # For same repo, branch, testbed, testcase, file_path, module_path
    # Only keep earliest start_checking_time and latest end_checking_time
    unique_failures = {}
    for detail in failure_details:
        key = (detail["repo"], detail["branch"], detail["testbed"], detail["testcase"],
               detail["file_path"], detail["module_path"])
        if key not in unique_failures:
            unique_failures[key] = detail
        else:
            existing = unique_failures[key]
            if detail["start_time"] < existing["start_time"]:
                existing["start_time"] = detail["start_time"]
            if detail["end_time"] > existing["end_time"]:
                existing["end_time"] = detail["end_time"]
    return list(unique_failures.values())


def analyze_candidates(kusto, lookback_days):
    now = dt.datetime.now(tz=timezone.utc)
    start = now - timedelta(days=lookback_days)
    end = now

    # 1) aggregated PR vs Baseline
    failure_details = []
    baseline_failures, pr_failures = get_pr_result_summary(kusto, start, end)
    if len(baseline_failures) > 0:
        logger.info(f"Total BaselineTest failures found: {baseline_failures}")
        failure_details = get_failure_details(kusto, failure_details, baseline_failures, "BaselineTest")
    if len(pr_failures) > 0:
        logger.info(f"Total PRTest failures found: {pr_failures}")
        failure_details = get_failure_details(kusto, failure_details, pr_failures, "PRTest")

    failure_details = remove_duplicates_failures(failure_details)
    logger.info(f"Total unique failure details to analyze: {failure_details}")

    all_commit_info = get_all_commits_info(failure_details)
    logger.info(f"Total commit info entries found: {all_commit_info}")

    return all_commit_info


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--lookback-days", type=int, default=QUERY_DAYS_RANGE)
    args = p.parse_args()

    kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(cluster, access_token)
    kusto_client = KustoClient(kcsb)
    analyze_candidates(kusto_client, args.lookback_days)


if __name__ == "__main__":
    main()
