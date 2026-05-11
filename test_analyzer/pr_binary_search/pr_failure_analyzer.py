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
import json
import uuid
import logging
import requests
import argparse
import datetime as dt
from datetime import timezone, timedelta
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder
from azure.kusto.data.exceptions import KustoServiceError
from config import (
    ALLOWED_BRANCHES,
    DEFAULT_FAILURE_INFO_FILE,
    KUSTO_DATABASE,
    KUSTO_FAILURE_MAPPING,
    KUSTO_FAILURE_TABLE,
    SUPPORTED_PUBLIC_REPOS,
)
from issue_close_analyzer import analyze_issue_close_with_conditional_mark
from kusto_uploader import ingest_records_from_env

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)

# CheckerType derivation from TestPlanName — matches pr_test_result_summary.py logic
CHECKER_TYPE_CASE_EXPR = '''case(
    TestPlanName matches regex ("kvmtest-t0_"), "t0_checker",
    TestPlanName matches regex ("kvmtest-t0-sonic_"), "t0-sonic_checker",
    TestPlanName matches regex ("kvmtest-t0-2vlans_"), "t0-2vlans_checker",
    TestPlanName matches regex ("kvmtest-t1-lag_"), "t1_checker",
    TestPlanName matches regex ("kvmtest-multi-asic-t1_"), "t1-multi-asic_checker",
    TestPlanName matches regex ("kvmtest-dualtor-t0_"), "dualtor_checker",
    TestPlanName matches regex ("kvmtest-dpu_"), "dpu_checker",
    TestPlanName matches regex ("kvmtest-t2_"), "t2_checker",
    "other")'''
DATABASE = KUSTO_DATABASE
ingest_cluster = os.environ.get("KUSTO_CLUSTER_INGEST_URL", None)
cluster = ingest_cluster.replace("ingest-", "") if ingest_cluster else None
access_token = os.environ.get("ACCESS_TOKEN", None)
github_api_token = os.environ.get("GIT_API_TOKEN", None)
TOTAL_COUNT_THRESHOLD = os.environ.get("TOTAL_TEST_COUNT_THRESHOLD", 10)
PREVIOUS_SUCCESS_THRESHOLD = os.environ.get("PREVIOUS_SUCCESS_THRESHOLD", 0.7)
PR_LOW_SUCCESS_THRESHOLD = os.environ.get("PR_LOW_SUCCESS_THRESHOLD", 0.5)
BASELINE_LOW_SUCCESS_THRESHOLD = os.environ.get("BASELINE_LOW_SUCCESS_THRESHOLD", 0.5)
QUERY_DAYS_RANGE = int(os.environ.get("QUERY_DAYS_RANGE", 1))
FAILURE_WINDOW_BUFFER_HOURS = int(os.environ.get("FAILURE_WINDOW_BUFFER_HOURS", 6))
FAILURE_WINDOW_FALLBACK_HOURS = int(os.environ.get("FAILURE_WINDOW_FALLBACK_HOURS", 24))
LAST_GOOD_MAX_LOOKBACK_DAYS = int(os.environ.get("LAST_GOOD_MAX_LOOKBACK_DAYS", 14))
LAST_GOOD_SEARCH_STEP_DAYS = int(os.environ.get("LAST_GOOD_SEARCH_STEP_DAYS", 30))
INCLUDE_NEXT_COMMIT_AFTER_WINDOW = os.environ.get("INCLUDE_NEXT_COMMIT_AFTER_WINDOW", "true").lower() in (
    "1", "true", "yes", "on"
)
KUSTO_OUTPUT_TABLE = KUSTO_FAILURE_TABLE


def parse_bool_arg(value):
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"Invalid boolean value: {value}")


def isoformat_kusto(dtobj: dt.datetime) -> str:
    return dtobj.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def execute_kusto_query_rows(kusto, query, query_name):
    try:
        return kusto.execute_query(DATABASE, query).primary_results[0].to_dict()['data']
    except KustoServiceError as exc:
        resp = exc.get_raw_http_response()
        status = getattr(resp, "status_code", "unknown")
        body = (getattr(resp, "text", "") or "").strip()
        body_preview = body[:500] if body else "<empty>"
        logger.error(
            f"Kusto query failed: {query_name}, status={status}, "
            f"cluster={cluster}, database={DATABASE}, response_body_preview={body_preview}"
        )
        raise


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


def get_next_commit_after_time(repo, branch, end_time):
    """
    Return the earliest commit strictly after `end_time` on `branch`.
    """
    headers = {"Authorization": f"token {github_api_token}", "Accept": "application/vnd.github+json"}
    if not github_api_token:
        return None

    url = f"https://api.github.com/repos/{repo}/commits"
    params = {
        "sha": branch,
        "since": end_time,
        "per_page": 100,
    }
    next_commit = None
    while url:
        response = requests.get(url, headers=headers, params=params, timeout=(3.05, 30))
        if response.status_code != 200:
            logger.error(f"GitHub API error {response.status_code} when fetching next commit: {response.text}")
            return None
        data = response.json()
        if not data:
            break
        for item in data:
            commit_date = item["commit"]["author"]["date"]
            if commit_date <= end_time:
                continue
            if not next_commit or commit_date < next_commit["date"]:
                next_commit = {"sha": item["sha"], "date": commit_date}
        if next_commit:
            break
        if 'next' in response.links:
            url = response.links['next']['url']
            params = None
        else:
            url = None
    return next_commit


def get_all_commits_info(failure_details):
    """
    Return list of commit SHAs merged into `branch` (if provided) between since and until.
    Falls back to listing commits on the branch with since/until. Requires GITHUB_TOKEN.
    """
    all_commit_info = []
    commit_cache = {}
    for detail in failure_details:
        repo = detail["repo"]
        branch = detail["branch"]
        start_time = detail["start_time"]
        end_time = detail["end_time"]
        test_scripts = {detail["checker"]: [detail["file_path"]]}
        cache_key = (repo, branch, start_time, end_time)
        if cache_key in commit_cache:
            commits = commit_cache[cache_key]
        else:
            commits = get_github_commits(repo, branch, start_time, end_time)
            # Sort commits oldest-first (ascending by date).
            # DynamicParallelBisect expects index 0 = oldest (good) and index N-1 = newest (bad).
            commits = sorted(commits, key=lambda x: x["date"])
            if INCLUDE_NEXT_COMMIT_AFTER_WINDOW:
                next_commit = get_next_commit_after_time(repo, branch, end_time)
                if next_commit and all(c["sha"] != next_commit["sha"] for c in commits):
                    commits.append(next_commit)
            commit_cache[cache_key] = commits
        if len(commits) > 0:
            commit_info = {
                "repo": repo,
                "branch": branch,
                "checker": detail["checker"],
                "testcase": detail["testcase"],
                "file_path": detail["file_path"],
                "module_path": detail["module_path"],
                "trigger_type": detail["trigger_type"],
                "test_scripts": test_scripts,
                "commits": commits
            }
            all_commit_info.append(commit_info)

    return all_commit_info


def _entry_key(entry):
    return (
        entry.get("repo"),
        entry.get("branch"),
        entry.get("checker"),
        entry.get("testcase"),
        entry.get("file_path"),
        entry.get("module_path"),
        entry.get("trigger_type"),
    )


def build_kusto_records(all_failure_entries, all_commit_info, run_id):
    commit_map = {}
    for item in all_commit_info:
        key = (
            item.get("repo"),
            item.get("branch"),
            item.get("checker"),
            item.get("testcase"),
            item.get("file_path"),
            item.get("module_path"),
            item.get("trigger_type"),
        )
        commit_map[key] = item.get("commits", [])

    output = []
    for entry in all_failure_entries:
        key = _entry_key(entry)
        commits = commit_map.get(key, [])
        test_scripts = {entry.get("checker"): [entry.get("file_path")]}
        likely_issue_close = bool(entry.get("result_type") == "issue_close_confirmed")
        if likely_issue_close:
            raw_failure_info = {
                "issue_close_check": {
                    "prev_day": entry.get("issue_close_prev_day", {}),
                    "bad_day": entry.get("issue_close_bad_day", {}),
                },
                "issue_close_analysis": entry.get("issue_close_analysis", {}),
            }
        else:
            raw_failure_info = {
                "repo": entry.get("repo"),
                "branch": entry.get("branch"),
                "test_scripts": test_scripts,
                "commits": commits,
                "issue_close_analysis": entry.get("issue_close_analysis", {}),
            }
        record = {
            "AnalyzerRunId": run_id,
            "TriggerType": entry.get("trigger_type"),
            "SourceRepo": entry.get("repo"),
            "Branch": entry.get("branch"),
            "CheckerType": entry.get("checker"),
            "FilePath": entry.get("file_path"),
            "ModulePath": entry.get("module_path"),
            "TestCase": entry.get("testcase"),
            "FirstBadTime": entry.get("first_bad_time"),
            "LastGoodTime": entry.get("last_good_time"),
            "FailureWindowStart": entry.get("start_time"),
            "FailureWindowEnd": entry.get("end_time"),
            "LikelyIssueClose": likely_issue_close,
            "CommitCount": len(commits),
            "Commits": commits,
            "RawFailureInfo": raw_failure_info,
            "UploadTime": isoformat_kusto(dt.datetime.now(tz=timezone.utc)),
        }
        output.append(record)
    return output


def get_pr_result_summary(kusto, start, end):
    """
    Query V2TestCases directly (joined with TestPlans) to detect test regressions.
    This replaces the previous approach of querying the pre-aggregated
    PRTestCaseResultSummary table, eliminating the 4-hour delay.
    """
    supported_repos = ', '.join(f'"{repo}"' for repo in SUPPORTED_PUBLIC_REPOS)
    query = f'''
    TestPlans
    | where EndTime between (datetime({isoformat_kusto(start)}) .. datetime({isoformat_kusto(end)}))
    | where TriggerType in ("PRTest", "BaselineTest")
    | where TestPlanName !contains "optional"
    | where SourceRepo in ({supported_repos})
    | extend CheckerType = {CHECKER_TYPE_CASE_EXPR}
    | where CheckerType != "other"
    | extend Branch = TestBranch
    | project TestPlanId, TriggerType, CheckerType, Branch, SourceRepo
    | join kind=inner (
        V2TestCases
        | where EndTime between (datetime({isoformat_kusto(start)}) .. datetime({isoformat_kusto(end)}))
        | where Result in ("success", "failure", "error", "skipped")
        | extend TestCase = extract("^(.+?)(\\\\[|$)", 1, TestCase)
        | project TestPlanId, FilePath, ModulePath, TestCase, Result
    ) on TestPlanId
    | summarize
        Success = countif(Result == "success"),
        Failure = countif(Result == "failure"),
        Error = countif(Result == "error"),
        Skip = countif(Result == "skipped"),
        Total = count()
        by SourceRepo, Branch, CheckerType, FilePath, ModulePath, TestCase, TriggerType
    | where (Total - Skip) > {TOTAL_COUNT_THRESHOLD}
    | extend SuccessRate = todouble(Success) / todouble(Success + Failure + Error)
    | project TriggerType, SourceRepo, Branch, CheckerType, FilePath, ModulePath, TestCase, SuccessRate
    '''
    query_result = execute_kusto_query_rows(kusto, query, "get_pr_result_summary")
    baseline_failures = []
    pr_failures = []

    for row in query_result:
        if row['TriggerType'] == 'BaselineTest' and float(row['SuccessRate']) < float(BASELINE_LOW_SUCCESS_THRESHOLD):
            baseline_failures.append(row)
        elif row['TriggerType'] == 'PRTest' and float(row['SuccessRate']) < float(PR_LOW_SUCCESS_THRESHOLD):
            pr_failures.append(row)

    # Check if baseline and pr failures have common entries
    # If so, remove them from pr_failures to avoid duplicate analysis
    pr_keys = {(row['SourceRepo'], row['Branch'], row['TriggerType'], row['ModulePath'], row['TestCase'])
               for row in pr_failures}
    baseline_failures = [row for row in baseline_failures if (
        row['SourceRepo'], row['Branch'], row['TriggerType'], row['ModulePath'], row['TestCase']) not in pr_keys]

    return baseline_failures, pr_failures


def is_likely_unskipped_by_issue_close(kusto, row, trigger_type, first_bad_time):
    """
    Heuristic:
    Compare previous day vs first bad day:
    - previous day has zero Success/Failure/Error
    - first bad day has non-zero Failure/Error
    This pattern likely indicates the test was unskipped due to issue close.
    """
    prev_day_start = first_bad_time - timedelta(days=1)
    bad_day_start = first_bad_time
    bad_day_end = first_bad_time + timedelta(days=1)
    prev_start_str = isoformat_kusto(prev_day_start)
    bad_end_str = isoformat_kusto(bad_day_end)
    query = f'''
    let test_plans = TestPlans
    | where EndTime between (datetime({prev_start_str}) .. datetime({bad_end_str}))
    | where TriggerType == "{trigger_type}"
    | where SourceRepo == "{row['SourceRepo']}"
    | where TestBranch == "{row['Branch']}"
    | extend CheckerType = {CHECKER_TYPE_CASE_EXPR}
    | where CheckerType == "{row['CheckerType']}"
    | project TestPlanId, EndTime;
    test_plans
    | join kind=inner (
        V2TestCases
        | where EndTime between (datetime({prev_start_str}) .. datetime({bad_end_str}))
        | where Result in ("success", "failure", "error")
        | extend TestCase = extract("^(.+?)(\\\\[|$)", 1, TestCase)
        | where FilePath == "{row['FilePath']}"
        | where ModulePath == "{row['ModulePath']}"
        | where TestCase == "{row['TestCase']}"
        | project TestPlanId, Result, EndTime
    ) on TestPlanId
    | extend Day = format_datetime(EndTime1, "yyyy-MM-dd")
    | summarize Success=countif(Result == "success"), Failure=countif(Result == "failure"),
        Error=countif(Result == "error"), TotalRows=count() by Day
    | order by Day asc
    '''
    result = execute_kusto_query_rows(kusto, query, "is_likely_unskipped_by_issue_close")
    logger.info(f"Checking if likely unskipped by issue close for {row['TestCase']}")
    logger.info(f"Result: {result}")

    day_stats = {}
    for item in result:
        day_key = item.get("Day")
        if not day_key:
            continue
        day_stats[day_key] = {
            "Success": int(item.get("Success") or 0),
            "Failure": int(item.get("Failure") or 0),
            "Error": int(item.get("Error") or 0),
            "TotalRows": int(item.get("TotalRows") or 0),
        }

    prev_day_key = prev_day_start.strftime("%Y-%m-%d")
    bad_day_key = bad_day_start.strftime("%Y-%m-%d")
    prev = day_stats.get(prev_day_key, {"Success": 0, "Failure": 0, "Error": 0, "TotalRows": 0})
    bad = day_stats.get(bad_day_key, {"Success": 0, "Failure": 0, "Error": 0, "TotalRows": 0})

    prev_all_zero = prev["Success"] == 0 and prev["Failure"] == 0 and prev["Error"] == 0
    bad_has_fail_or_error = (bad["Failure"] > 0) or (bad["Error"] > 0)
    likely = prev_all_zero and bad_has_fail_or_error

    return likely, {"prev_day": prev, "bad_day": bad}


def find_last_good_time_before_first_bad(kusto, row, trigger_type, first_bad_time,
                                         max_lookback_days=None):
    """
    Find the nearest historical healthy point before first_bad_time with expanded lookback.
    Queries V2TestCases + TestPlans directly for precise time-based detection.
    """
    end = first_bad_time
    remaining_days = max(0, max_lookback_days if max_lookback_days is not None else LAST_GOOD_MAX_LOOKBACK_DAYS)
    step_days = max(1, LAST_GOOD_SEARCH_STEP_DAYS)

    while remaining_days > 0:
        days = min(step_days, remaining_days)
        start = end - timedelta(days=days)
        query = f'''
        let test_plans = TestPlans
        | where EndTime between (datetime({isoformat_kusto(start)}) .. datetime({isoformat_kusto(end)}))
        | where TriggerType == "{trigger_type}"
        | where SourceRepo == "{row['SourceRepo']}"
        | where TestBranch == "{row['Branch']}"
        | extend CheckerType = {CHECKER_TYPE_CASE_EXPR}
        | where CheckerType == "{row['CheckerType']}"
        | project TestPlanId, EndTime;
        test_plans
        | join kind=inner (
            V2TestCases
            | where EndTime between (datetime({isoformat_kusto(start)}) .. datetime({isoformat_kusto(end)}))
            | where Result in ("success", "failure", "error")
            | extend TestCase = extract("^(.+?)(\\\\[|$)", 1, TestCase)
            | where FilePath == "{row['FilePath']}"
            | where ModulePath == "{row['ModulePath']}"
            | where TestCase == "{row['TestCase']}"
            | project TestPlanId, Result, EndTime
        ) on TestPlanId
        | extend Day = format_datetime(EndTime1, "yyyy-MM-dd")
        | summarize
            Success = countif(Result == "success"),
            Failure = countif(Result == "failure"),
            Error = countif(Result == "error"),
            Total = count(),
            LatestEndTime = max(EndTime1)
            by Day
        | where Total > 0
        | extend SuccessRate = todouble(Success) / todouble(Success + Failure + Error)
        | where SuccessRate >= {PREVIOUS_SUCCESS_THRESHOLD}
        | order by Day desc
        | take 1
        '''
        rows = execute_kusto_query_rows(kusto, query, "find_last_good_time_before_first_bad")
        if rows:
            return rows[0].get("LatestEndTime")

        end = start
        remaining_days -= days

    return None


def get_failure_details(kusto, failure_details, all_failure_entries, failures, trigger_type,
                        query_start, query_end, max_search_range_days=None):
    for row in failures:
        query_time_range = f'''
        let test_plans = TestPlans
        | where EndTime between (datetime({isoformat_kusto(query_start)}) .. datetime({isoformat_kusto(query_end)}))
        | where TriggerType == "{trigger_type}"
        | where SourceRepo == "{row['SourceRepo']}"
        | where TestBranch == "{row['Branch']}"
        | extend CheckerType = {CHECKER_TYPE_CASE_EXPR}
        | where CheckerType == "{row['CheckerType']}"
        | project TestPlanId, EndTime;
        test_plans
        | join kind=inner (
            V2TestCases
            | where EndTime between (datetime({isoformat_kusto(query_start)}) .. datetime({isoformat_kusto(query_end)}))
            | where Result in ("success", "failure", "error")
            | extend TestCase = extract("^(.+?)(\\\\[|$)", 1, TestCase)
            | where FilePath == "{row['FilePath']}"
            | where ModulePath == "{row['ModulePath']}"
            | where TestCase == "{row['TestCase']}"
            | project TestPlanId, Result, EndTime
        ) on TestPlanId
        | extend Day = format_datetime(EndTime1, "yyyy-MM-dd")
        | summarize
            Success = countif(Result == "success"),
            Failure = countif(Result == "failure"),
            Error = countif(Result == "error"),
            Total = count()
            by Day
        | where Total > 0
        | extend SuccessRate = todouble(Success) / todouble(Success + Failure + Error)
        | project Day, SuccessRate
        | order by Day asc
        '''
        history_rows = execute_kusto_query_rows(kusto, query_time_range, "get_failure_details.query_time_range")
        if len(history_rows) == 0:
            logger.info(f"No failure time range found for {row['TestCase']}, skipping.")
            all_failure_entries.append({
                "repo": row['SourceRepo'],
                "branch": row['Branch'],
                "checker": row['CheckerType'],
                "testcase": row['TestCase'],
                "file_path": row['FilePath'],
                "module_path": row['ModulePath'],
                "trigger_type": trigger_type,
                "result_type": "no_history_rows",
                "first_bad_time": None,
                "last_good_time": None,
                "start_time": None,
                "end_time": None,
            })
            continue

        first_bad_time = None
        for item in history_rows:
            if float(item["SuccessRate"]) < float(PREVIOUS_SUCCESS_THRESHOLD):
                first_bad_time = dt.datetime.strptime(item["Day"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                break
        if not first_bad_time:
            logger.info(f"No first bad point found for {row['TestCase']}, skipping.")
            all_failure_entries.append({
                "repo": row['SourceRepo'],
                "branch": row['Branch'],
                "checker": row['CheckerType'],
                "testcase": row['TestCase'],
                "file_path": row['FilePath'],
                "module_path": row['ModulePath'],
                "trigger_type": trigger_type,
                "result_type": "no_first_bad_point",
                "first_bad_time": None,
                "last_good_time": None,
                "start_time": None,
                "end_time": None,
            })
            continue

        likely_issue_close, issue_close_stats = is_likely_unskipped_by_issue_close(
            kusto, row, trigger_type, first_bad_time)
        if likely_issue_close:
            prev = issue_close_stats["prev_day"]
            bad = issue_close_stats["bad_day"]
            start_time = first_bad_time - timedelta(hours=FAILURE_WINDOW_FALLBACK_HOURS)
            end_time = first_bad_time + timedelta(hours=FAILURE_WINDOW_BUFFER_HOURS)
            issue_close_analysis = analyze_issue_close_with_conditional_mark(
                row['FilePath'],
                row['ModulePath'],
                row['TestCase'],
                first_bad_time,
                row['Branch'],
            )
            result_type = "issue_close_confirmed" if issue_close_analysis["confirmed"] else "candidate"
            detail = {
                "repo": row['SourceRepo'],
                "branch": row['Branch'],
                "checker": row['CheckerType'],
                "testcase": row['TestCase'],
                "file_path": row['FilePath'],
                "module_path": row['ModulePath'],
                "trigger_type": trigger_type,
                "result_type": result_type,
                "start_time": isoformat_kusto(start_time),
                "end_time": isoformat_kusto(end_time),
                "first_bad_time": isoformat_kusto(first_bad_time),
                "last_good_time": None,
                "issue_close_prev_day": prev,
                "issue_close_bad_day": bad,
                "issue_close_analysis": issue_close_analysis,
            }
            if issue_close_analysis["confirmed"]:
                logger.info(
                    f"Confirmed issue-close regression for {row['TestCase']}: "
                    f"{issue_close_analysis['issues']}"
                )
            else:
                logger.info(
                    f"Issue-close heuristic not confirmed for {row['TestCase']}; "
                    f"keeping it as binary-search candidate. analysis={issue_close_analysis}"
                )

            failure_details.append(dict(detail))
            all_failure_entries.append(dict(detail))
            continue

        last_good_time = None
        for item in history_rows:
            run_day = dt.datetime.strptime(item["Day"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if run_day >= first_bad_time:
                break
            if float(item["SuccessRate"]) >= float(PREVIOUS_SUCCESS_THRESHOLD):
                last_good_time = run_day

        if not last_good_time:
            last_good_time = find_last_good_time_before_first_bad(
                kusto, row, trigger_type, first_bad_time,
                max_lookback_days=max_search_range_days)
            if last_good_time:
                logger.info(
                    f"Found historical last_good_time outside current lookback for {row['TestCase']}: {last_good_time}"
                )

        if last_good_time:
            start_time = last_good_time - timedelta(hours=FAILURE_WINDOW_BUFFER_HOURS)
        else:
            # If no historical healthy point in lookback window, keep fallback minimal window.
            start_time = first_bad_time - timedelta(hours=FAILURE_WINDOW_FALLBACK_HOURS)
        end_time = first_bad_time + timedelta(hours=FAILURE_WINDOW_BUFFER_HOURS)
        logger.info(
            f"Found narrowed failure window for {row['TestCase']}: "
            f"first_bad={first_bad_time}, last_good={last_good_time}, "
            f"window=({start_time} - {end_time})")

        # Use narrowed change window to fetch commits close to the regression boundary.
        detail = {
            "repo": row['SourceRepo'],
            "branch": row['Branch'],
            "checker": row['CheckerType'],
            "testcase": row['TestCase'],
            "file_path": row['FilePath'],
            "module_path": row['ModulePath'],
            "trigger_type": trigger_type,
            "result_type": "candidate",
            "start_time": isoformat_kusto(start_time),
            "end_time": isoformat_kusto(end_time),
            "first_bad_time": isoformat_kusto(first_bad_time),
            "last_good_time": isoformat_kusto(last_good_time) if last_good_time else None,
            "issue_close_prev_day": issue_close_stats.get("prev_day", {}),
            "issue_close_bad_day": issue_close_stats.get("bad_day", {}),
            "issue_close_analysis": {},
        }
        failure_details.append(detail)
        all_failure_entries.append(dict(detail))

    return failure_details, all_failure_entries


def remove_duplicates_failures(failure_details):
    # For same repo, branch, checker, testcase, file_path, module_path
    # Only keep earliest start_checking_time and latest end_checking_time
    unique_failures = {}
    for detail in failure_details:
        key = (detail["repo"], detail["branch"], detail["checker"], detail["testcase"],
               detail["file_path"], detail["module_path"])
        if key not in unique_failures:
            unique_failures[key] = detail
        else:
            existing = unique_failures[key]
            if detail["start_time"] < existing["start_time"]:
                existing["start_time"] = detail["start_time"]
            if detail["end_time"] > existing["end_time"]:
                existing["end_time"] = detail["end_time"]
            if detail.get("first_bad_time") and (
                not existing.get("first_bad_time") or detail["first_bad_time"] < existing["first_bad_time"]
            ):
                existing["first_bad_time"] = detail["first_bad_time"]
            if detail.get("last_good_time") and (
                not existing.get("last_good_time") or detail["last_good_time"] > existing["last_good_time"]
            ):
                existing["last_good_time"] = detail["last_good_time"]
    return list(unique_failures.values())


def deduplicate_failure_entries(entries):
    # Dedup for Kusto output by testcase identity.
    priority = {
        "issue_close_confirmed": 4,
        "candidate": 3,
        "issue_close_suspected": 2,
        "no_first_bad_point": 1,
        "no_history_rows": 0,
    }
    unique = {}
    for entry in entries:
        key = (
            entry.get("trigger_type"),
            entry.get("repo"),
            entry.get("branch"),
            entry.get("checker"),
            entry.get("file_path"),
            entry.get("module_path"),
            entry.get("testcase"),
        )
        if key not in unique:
            unique[key] = entry
            continue

        existing = unique[key]
        existing_pri = priority.get(existing.get("result_type"), -1)
        new_pri = priority.get(entry.get("result_type"), -1)

        if new_pri > existing_pri:
            unique[key] = entry
            continue

        # If same priority and both candidates, merge window boundaries.
        if new_pri == existing_pri == priority["candidate"]:
            if entry.get("start_time") and (
                not existing.get("start_time") or entry["start_time"] < existing["start_time"]
            ):
                existing["start_time"] = entry["start_time"]
            if entry.get("end_time") and (
                not existing.get("end_time") or entry["end_time"] > existing["end_time"]
            ):
                existing["end_time"] = entry["end_time"]
            if entry.get("first_bad_time") and (
                not existing.get("first_bad_time") or entry["first_bad_time"] < existing["first_bad_time"]
            ):
                existing["first_bad_time"] = entry["first_bad_time"]
            if entry.get("last_good_time") and (
                not existing.get("last_good_time") or entry["last_good_time"] > existing["last_good_time"]
            ):
                existing["last_good_time"] = entry["last_good_time"]

    return list(unique.values())


def analyze_candidates(kusto, lookback_days, failure_info_file, allowed_branches=None,
                       max_search_range_days=None):
    now = dt.datetime.now(tz=timezone.utc)
    # Truncate to the start of today (00:00 UTC) so that lookback_days=1
    # always includes yesterday's full day.  V2TestCases results are
    # bucketed by day, so "1 day ago" from e.g. 10:16 UTC must reach
    # yesterday's 00:00, not just 24 hours back.
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    start = today_start - timedelta(days=lookback_days)
    end = now

    failure_details = []
    all_failure_entries = []
    baseline_failures, pr_failures = get_pr_result_summary(kusto, start, end)
    if allowed_branches is not None:
        baseline_failures = [row for row in baseline_failures if row.get("Branch") in allowed_branches]
        pr_failures = [row for row in pr_failures if row.get("Branch") in allowed_branches]
        logger.info(f"Applied branch filter: {sorted(allowed_branches)}")
    if len(baseline_failures) > 0:
        logger.info(f"Total BaselineTest failures found: {baseline_failures}")
        failure_details, all_failure_entries = get_failure_details(
            kusto, failure_details, all_failure_entries, baseline_failures, "BaselineTest", start, end,
            max_search_range_days=max_search_range_days
        )
    if len(pr_failures) > 0:
        logger.info(f"Total PRTest failures found: {pr_failures}")
        failure_details, all_failure_entries = get_failure_details(
            kusto, failure_details, all_failure_entries, pr_failures, "PRTest", start, end,
            max_search_range_days=max_search_range_days
        )

    failure_details = remove_duplicates_failures(failure_details)
    logger.info(f"Total unique failure details to analyze: {failure_details}")
    before = len(all_failure_entries)
    all_failure_entries = deduplicate_failure_entries(all_failure_entries)
    logger.info(
        f"Deduplicated failure entries for Kusto output: before={before}, after={len(all_failure_entries)}"
    )

    all_commit_info = get_all_commits_info(failure_details)
    logger.info(f"Total commit info entries found: {all_commit_info}")

    run_id = str(uuid.uuid4())
    kusto_records = build_kusto_records(all_failure_entries, all_commit_info, run_id)
    logger.info(f"Kusto failure records generated for table {KUSTO_OUTPUT_TABLE}: {len(kusto_records)}")
    if failure_info_file:
        with open(failure_info_file, "w") as f:
            json.dump(kusto_records, f, indent=2)
        logger.info(f"Failure info written to {failure_info_file}")

    return all_commit_info, kusto_records


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--lookback_days", type=int, default=QUERY_DAYS_RANGE, help="Lookback days")
    p.add_argument("--failure_info_file", type=str, default=DEFAULT_FAILURE_INFO_FILE, help="Output failure info file")
    p.add_argument("--upload_kusto", type=parse_bool_arg, default=False, help="Upload generated failure info to Kusto")
    p.add_argument("--max_search_range_days", type=int, default=LAST_GOOD_MAX_LOOKBACK_DAYS,
                   help="Max days to search back for commit range (default: %(default)s). "
                        "Controls how far back to look for the last healthy test run.")
    args = p.parse_args()

    if not cluster:
        raise RuntimeError("Missing KUSTO_CLUSTER_INGEST_URL environment variable.")
    if not access_token:
        raise RuntimeError("Missing ACCESS_TOKEN environment variable.")

    kcsb = KustoConnectionStringBuilder.with_aad_application_token_authentication(cluster, access_token)
    kusto_client = KustoClient(kcsb)
    logger.info(f"Kusto target: cluster={cluster}, database={DATABASE}")
    logger.info(
        f"Using thresholds: TOTAL_COUNT_THRESHOLD={TOTAL_COUNT_THRESHOLD}, "
        f"PREVIOUS_SUCCESS_THRESHOLD={PREVIOUS_SUCCESS_THRESHOLD}, "
        f"PR_LOW_SUCCESS_THRESHOLD={PR_LOW_SUCCESS_THRESHOLD}, "
        f"BASELINE_LOW_SUCCESS_THRESHOLD={BASELINE_LOW_SUCCESS_THRESHOLD}")
    logger.info(f"Include next commit after window: {INCLUDE_NEXT_COMMIT_AFTER_WINDOW}")
    logger.info(f"Supported public repos: {SUPPORTED_PUBLIC_REPOS}")
    logger.info(f"Max search range: {args.max_search_range_days} days")
    _, kusto_records = analyze_candidates(
        kusto_client,
        args.lookback_days,
        args.failure_info_file,
        allowed_branches=set(ALLOWED_BRANCHES),
        max_search_range_days=args.max_search_range_days,
    )
    if args.upload_kusto:
        ingest_records_from_env(
            kusto_records,
            database=KUSTO_DATABASE,
            table=KUSTO_FAILURE_TABLE,
            mapping=KUSTO_FAILURE_MAPPING,
        )


if __name__ == "__main__":
    main()
