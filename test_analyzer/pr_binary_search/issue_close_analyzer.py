import glob
import logging
import os
import re
import datetime as dt
from datetime import timedelta

import requests
import yaml


logger = logging.getLogger(__name__)

ISSUE_CLOSE_CONFIRM_WINDOW_DAYS = int(os.environ.get("ISSUE_CLOSE_CONFIRM_WINDOW_DAYS", 7))
ISSUE_CLOSE_FUTURE_GRACE_HOURS = int(os.environ.get("ISSUE_CLOSE_FUTURE_GRACE_HOURS", 24))
CONDITIONAL_MARK_PATTERN = os.path.normpath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "tests",
        "common",
        "plugins",
        "conditional_mark",
        "tests_mark_conditions*.yaml",
    )
)
GITHUB_ISSUE_URL_RE = re.compile(r"https://github\.com/[^/\s]+/[^/\s]+/issues/\d+")

_CONDITIONAL_MARK_CACHE = None
_GITHUB_ISSUE_CACHE = {}


def parse_iso_datetime(dt_str):
    if not dt_str:
        return None
    return dt.datetime.fromisoformat(dt_str.replace("Z", "+00:00"))


def load_conditional_mark_data():
    global _CONDITIONAL_MARK_CACHE
    if _CONDITIONAL_MARK_CACHE is not None:
        return _CONDITIONAL_MARK_CACHE

    merged = {}
    file_paths = sorted(glob.glob(CONDITIONAL_MARK_PATTERN))
    for file_path in file_paths:
        try:
            with open(file_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            if isinstance(data, dict):
                merged.update(data)
        except yaml.YAMLError as exc:
            logger.error(f"Error parsing YAML file {file_path}: {exc}")

    _CONDITIONAL_MARK_CACHE = merged
    logger.info(f"Loaded conditional mark files: {len(file_paths)}, entries={len(merged)}")
    return merged


def testcase_key_candidates(file_path, module_path, testcase):
    candidates = []
    testcase_base = (testcase or "").split("[", 1)[0]
    file_module = os.path.splitext(file_path.replace("/", "."))[0] if file_path else ""

    class_path = None
    if module_path and file_module and module_path.startswith(file_module + "."):
        class_path = module_path[len(file_module) + 1:]

    if file_path and testcase_base and class_path:
        candidates.append(f"{file_path}::{class_path}::{testcase_base}")
    if file_path and testcase_base:
        candidates.append(f"{file_path}::{testcase_base}")
    if file_path:
        candidates.append(file_path)
    return candidates


def find_conditional_mark_entries(file_path, module_path, testcase):
    conditions = load_conditional_mark_data()
    candidates = testcase_key_candidates(file_path, module_path, testcase)
    matches = []

    for key, value in conditions.items():
        if not isinstance(key, str):
            continue
        for candidate in candidates:
            if key == candidate or key.startswith(candidate + "["):
                matches.append({"key": key, "value": value})
                break

    if not matches and file_path and file_path in conditions:
        matches.append({"key": file_path, "value": conditions[file_path]})

    return matches


def extract_issue_urls(obj):
    urls = set()
    if isinstance(obj, str):
        urls.update(GITHUB_ISSUE_URL_RE.findall(obj))
    elif isinstance(obj, list):
        for item in obj:
            urls.update(extract_issue_urls(item))
    elif isinstance(obj, dict):
        for value in obj.values():
            urls.update(extract_issue_urls(value))
    return urls


def github_issue_api_url(issue_url):
    return issue_url.replace("https://github.com/", "https://api.github.com/repos/")


def fetch_github_issue(issue_url, github_api_token=None):
    if issue_url in _GITHUB_ISSUE_CACHE:
        return _GITHUB_ISSUE_CACHE[issue_url]

    headers = {"Accept": "application/vnd.github+json"}
    if github_api_token:
        headers["Authorization"] = f"token {github_api_token}"

    api_url = github_issue_api_url(issue_url)
    try:
        response = requests.get(api_url, headers=headers, timeout=(3.05, 20))
        response.raise_for_status()
        payload = response.json()
        result = {
            "url": issue_url,
            "state": payload.get("state"),
            "state_reason": payload.get("state_reason"),
            "closed_at": payload.get("closed_at"),
            "title": payload.get("title"),
        }
    except Exception as exc:
        logger.warning(f"Failed to fetch GitHub issue metadata for {issue_url}: {exc}")
        result = {
            "url": issue_url,
            "error": str(exc),
        }

    _GITHUB_ISSUE_CACHE[issue_url] = result
    return result


def analyze_issue_close_with_conditional_mark(
    file_path,
    module_path,
    testcase,
    first_bad_time,
    branch,
    github_api_token=None,
):
    matched_entries = find_conditional_mark_entries(file_path, module_path, testcase)
    if not matched_entries:
        return {
            "confirmed": False,
            "verdict": "no_conditional_mark_match",
            "matched_entries": [],
            "issues": [],
        }

    first_bad_dt = first_bad_time
    lower_bound = first_bad_dt - timedelta(days=ISSUE_CLOSE_CONFIRM_WINDOW_DAYS)
    upper_bound = first_bad_dt + timedelta(hours=ISSUE_CLOSE_FUTURE_GRACE_HOURS)

    issue_urls = set()
    for entry in matched_entries:
        issue_urls.update(extract_issue_urls(entry["value"]))

    issues = []
    confirmed = False
    for issue_url in sorted(issue_urls):
        issue = dict(fetch_github_issue(issue_url, github_api_token=github_api_token))
        closed_at_dt = parse_iso_datetime(issue.get("closed_at"))
        closed_in_window = bool(closed_at_dt and lower_bound <= closed_at_dt <= upper_bound)
        issue["closed_in_window"] = closed_in_window
        issues.append(issue)
        if issue.get("state") == "closed" and closed_in_window:
            confirmed = True

    verdict = "confirmed_recent_issue_close" if confirmed else "conditional_mark_match_but_no_recent_closed_issue"
    return {
        "confirmed": confirmed,
        "verdict": verdict,
        "branch": branch,
        "matched_entries": [entry["key"] for entry in matched_entries],
        "issues": issues,
    }
