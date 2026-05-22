"""
Standalone auto-revert pipeline for PR binary search results.

Reads binary search results from Kusto (PRBinarySearchResult table), finds
entries with RootCauseType == "bad_commit", and creates revert PRs in the
source repository using a local ``git revert`` (proper three-way merge).

Usage:
    python revert_handler.py --lookback_hours 48

Scoped to sonic-net/sonic-buildimage only.  Skips if a revert PR already
exists.  Each bad commit is processed independently — errors on one do not
affect others.
"""

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile

import requests
import sys

from azure.kusto.data import KustoClient, KustoConnectionStringBuilder

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
KUSTO_DATABASE = "SonicTestData"
KUSTO_RESULT_TABLE = "PRBinarySearchResult"

# Only auto-revert commits in these repos.
REVERT_ALLOWED_REPOS = {"sonic-net/sonic-buildimage"}

# Deterministic branch prefix so we can detect duplicates.
REVERT_BRANCH_PREFIX = "auto-revert"

# Maximum number of changed files in a PR we're willing to auto-revert.
MAX_FILES_FOR_AUTO_REVERT = 50

# Timeout for HTTP requests (seconds).
HTTP_TIMEOUT = 30

# Strict repo format: owner/name with alphanumeric, hyphens, underscores.
REPO_FORMAT_RE = re.compile(r"^[\w.-]+/[\w.-]+$")


def parse_bool_arg(value):
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes"}:
        return True
    if normalized in {"0", "false", "no"}:
        return False
    raise argparse.ArgumentTypeError(f"Invalid boolean value: {value}")


# ── Kusto ───────────────────────────────────────────────────────────────────


def _validate_repo_format(source_repo):
    """Validate repo string to prevent KQL injection (#7)."""
    if not REPO_FORMAT_RE.match(source_repo):
        raise ValueError(
            f"Invalid repo format: {source_repo!r} "
            f"(expected 'owner/name')")


def fetch_bad_commit_results(kusto_client, lookback_hours, source_repo=None):
    """Fetch completed binary search results with RootCauseType == 'bad_commit'.

    Returns a list of dicts with keys: SourceRepo, Branch, BadCommit,
    CheckerType, FilePath, ModulePath, TestCase, AnalyzerRunId, SearchRunId,
    UploadTime.
    """
    repo_filter = ""
    if source_repo:
        _validate_repo_format(source_repo)
        repo_filter = f'| where SourceRepo == "{source_repo}"'

    query = f"""
    {KUSTO_RESULT_TABLE}
    | where UploadTime > ago({int(lookback_hours)}h)
    | where RootCauseType == "bad_commit"
    | where SearchCompleted == true
    | where isnotempty(BadCommit)
    {repo_filter}
    | summarize arg_max(UploadTime, *) by SourceRepo, BadCommit
    | project SourceRepo, Branch, BadCommit, CheckerType, FilePath,
              ModulePath, TestCase, AnalyzerRunId, SearchRunId, UploadTime
    | order by UploadTime desc
    """
    resp = kusto_client.execute(KUSTO_DATABASE, query)
    rows = []
    for row in resp.primary_results[0]:
        rows.append({col: row[col] for col in [
            "SourceRepo", "Branch", "BadCommit", "CheckerType", "FilePath",
            "ModulePath", "TestCase", "AnalyzerRunId", "SearchRunId",
            "UploadTime",
        ]})
    return rows


# ── GitHub API helpers ──────────────────────────────────────────────────────


def _github_headers(token):
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _revert_branch_name(bad_commit_short):
    """Deterministic branch name so concurrent runs won't create duplicates."""
    return f"{REVERT_BRANCH_PREFIX}/{bad_commit_short}"


def find_pr_for_commit(owner, repo, commit_sha, token):
    """Find the merged PR that introduced a commit.

    Uses the ``commits/{sha}/pulls`` endpoint (recommended over search).
    Returns the PR dict or None.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{commit_sha}/pulls"
    resp = requests.get(
        url, headers=_github_headers(token), timeout=HTTP_TIMEOUT)
    if resp.status_code != 200:
        logger.warning(
            "Failed to find PR for %s: HTTP %s",
            commit_sha, resp.status_code)
        return None

    for pr in resp.json():
        if (pr.get("merged_at")
                and pr.get("base", {}).get("ref") in ("master", "main")):
            return pr

    logger.info("No merged PR found for commit %s", commit_sha[:12])
    return None


def _find_existing_revert_pr(owner, repo, branch_name, base_branch, token):
    """Find an existing PR from *branch_name* into *base_branch* (any state).

    Returns the PR html_url or None.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls"
    resp = requests.get(
        url, headers=_github_headers(token), timeout=HTTP_TIMEOUT,
        params={
            "head": f"{owner}:{branch_name}",
            "base": base_branch,
            "state": "all",
        })
    if resp.status_code == 200 and resp.json():
        return resp.json()[0].get("html_url")
    return None


def check_already_reverted(owner, repo, original_pr_number,
                           bad_commit_short, base_branch, token):
    """Check if a revert PR already exists.

    Looks for an open/closed/merged PR whose title references the original PR.
    A branch alone is NOT sufficient (#4) — a previous partial failure may
    have left the branch without a PR.
    """
    # Check for an existing PR on our deterministic branch.
    branch_name = _revert_branch_name(bad_commit_short)
    pr_url = _find_existing_revert_pr(
        owner, repo, branch_name, base_branch, token)
    if pr_url:
        logger.info("Existing revert PR found on branch: %s", pr_url)
        return True

    # Broader search: any PR whose title mentions reverting the original.
    search_query = (
        f"repo:{owner}/{repo} is:pr "
        f"Revert #{original_pr_number} in:title")
    url = (f"{GITHUB_API}/search/issues"
           f"?q={requests.utils.quote(search_query)}")
    resp = requests.get(
        url, headers=_github_headers(token), timeout=HTTP_TIMEOUT)
    if resp.status_code == 200:
        items = resp.json().get("items", [])
        if items:
            pr_url = items[0].get("html_url", "")
            logger.info("Existing revert PR found via search: %s", pr_url)
            return True

    return False


def _get_commit(owner, repo, sha, token):
    """Fetch a commit object from GitHub."""
    url = f"{GITHUB_API}/repos/{owner}/{repo}/commits/{sha}"
    resp = requests.get(
        url, headers=_github_headers(token), timeout=HTTP_TIMEOUT)
    if resp.status_code != 200:
        return None
    return resp.json()


def _is_submodule_bump(commit_data):
    """Detect if a commit is primarily a submodule bump (risky to auto-revert).

    Checks for .gitmodules changes and for submodule pointer updates
    (type == "submodule" or mode == "160000"), which indicate actual
    submodule pointer changes.
    """
    files = commit_data.get("files", [])
    if not files:
        return False
    submodule_indicators = [
        f for f in files
        if f.get("filename", "").endswith(".gitmodules")
        or f.get("type") == "submodule"  # GitHub API marks gitlinks as "submodule"
    ]
    # Heuristic: small PR with submodule-related files is likely a bump.
    if len(files) <= 3 and submodule_indicators:
        return True
    return False


def _open_pull_request(owner, repo, branch_name, base_branch,
                       title, body, token):
    """Open a PR from branch_name into base_branch.  Returns PR URL or None.

    Handles 422 (already exists) gracefully by finding the existing PR.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls"
    payload = {
        "title": title,
        "head": branch_name,
        "base": base_branch,
        "body": body,
    }
    resp = requests.post(
        url, headers=_github_headers(token), json=payload,
        timeout=HTTP_TIMEOUT)
    if resp.status_code == 201:
        return resp.json().get("html_url")
    if resp.status_code == 422:
        logger.info("PR creation returned 422 (likely already exists)")
        existing = _find_existing_revert_pr(
            owner, repo, branch_name, base_branch, token)
        if existing:
            return existing
    logger.error(
        "Failed to create PR: HTTP %s %s",
        resp.status_code, resp.text[:200])
    return None


# ── Local git revert ────────────────────────────────────────────────────────


def _run_git(args, cwd, check=True):
    """Run a git command and return its stdout."""
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd, capture_output=True, text=True, timeout=300)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed (rc={result.returncode}): "
            f"{result.stderr.strip()}")
    return result


def _clone_and_revert(owner, repo, base_branch, merge_commit_sha,
                      revert_branch, revert_message, token):
    """Clone the repo, create a revert commit via ``git revert``, and push.

    Uses a shallow clone + fetch of the specific commit for efficiency.
    If the target commit is not reachable in the shallow history, the clone
    is unshallowed automatically.
    Returns the revert commit SHA, or None if the revert had conflicts.
    """
    clone_url = f"https://x-access-token:{token}@github.com/{owner}/{repo}.git"
    clone_dir = tempfile.mkdtemp(prefix="auto-revert-")
    try:
        logger.info("Cloning %s/%s (shallow)...", owner, repo)
        _run_git(
            ["clone", "--depth=1", "--branch", base_branch,
             "--single-branch", clone_url, clone_dir],
            cwd=clone_dir)

        # Set identity required for git revert/commit operations.
        _run_git(["config", "user.email", "sonicbld@microsoft.com"],
                 cwd=clone_dir)
        _run_git(["config", "user.name", "Sonic Build"], cwd=clone_dir)

        # Fetch enough history to perform the revert.
        _run_git(
            ["fetch", "--depth=50", "origin", base_branch],
            cwd=clone_dir)

        # Try to fetch the specific commit; if it's not reachable in the
        # shallow history, unshallow the full repo to guarantee access.
        fetch_result = _run_git(
            ["fetch", "origin", merge_commit_sha],
            cwd=clone_dir, check=False)
        if fetch_result.returncode != 0:
            logger.info(
                "Commit %s not reachable in shallow clone; unshallowing...",
                merge_commit_sha[:12])
            _run_git(["fetch", "--unshallow", "origin", base_branch],
                     cwd=clone_dir)
            _run_git(["fetch", "origin", merge_commit_sha], cwd=clone_dir)

        # Create revert branch from origin/<base_branch>.
        _run_git(
            ["checkout", "-b", revert_branch, f"origin/{base_branch}"],
            cwd=clone_dir)

        # Determine if this is a merge commit (>1 parent).
        result = _run_git(
            ["cat-file", "-p", merge_commit_sha],
            cwd=clone_dir)
        parent_count = result.stdout.count("\nparent ")
        # Account for first "parent" which doesn't have \n prefix.
        if result.stdout.startswith("parent "):
            parent_count += 1

        revert_cmd = ["revert", "--no-edit"]
        if parent_count > 1:
            revert_cmd += ["-m", "1"]
        revert_cmd.append(merge_commit_sha)

        revert_result = _run_git(revert_cmd, cwd=clone_dir, check=False)
        if revert_result.returncode != 0:
            # Conflict or other failure — abort and report.
            _run_git(["revert", "--abort"], cwd=clone_dir, check=False)
            logger.warning(
                "git revert failed (likely conflict): %s",
                revert_result.stderr.strip()[:300])
            return None

        # Amend commit message to include our metadata.
        _run_git(
            ["commit", "--amend", "-m", revert_message],
            cwd=clone_dir)

        # Push the branch.  If the branch already exists from a prior
        # partial run, force-push to overwrite it.
        push_result = _run_git(
            ["push", "origin", revert_branch, "--force"],
            cwd=clone_dir, check=False)
        if push_result.returncode != 0:
            logger.error(
                "git push failed: %s", push_result.stderr.strip()[:300])
            return None

        # Read back the commit SHA.
        sha_result = _run_git(["rev-parse", "HEAD"], cwd=clone_dir)
        return sha_result.stdout.strip()
    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)


# ── Core logic ──────────────────────────────────────────────────────────────


def create_revert_pr(owner, repo, branch, bad_commit, metadata, token):
    """Create a revert PR for a bad commit.

    Uses a local ``git revert`` to produce a proper three-way merge revert,
    which correctly handles subsequent commits on the branch.

    Args:
        metadata: dict with keys like CheckerType, FilePath, TestCase,
                  AnalyzerRunId.

    Returns a dict with revert status info.
    """
    short_sha = bad_commit[:12]
    logger.info("Processing %s/%s commit %s", owner, repo, short_sha)

    full_repo = f"{owner}/{repo}"
    if full_repo not in REVERT_ALLOWED_REPOS:
        logger.info(
            "Repo %s not in REVERT_ALLOWED_REPOS, skipping", full_repo)
        return {"status": "skipped", "reason": "repo_not_allowed"}

    # Find the original PR.
    original_pr = find_pr_for_commit(owner, repo, bad_commit, token)
    if not original_pr:
        logger.warning("Cannot find merged PR for %s, skipping", short_sha)
        return {"status": "skipped", "reason": "no_merged_pr_found"}

    pr_number = original_pr["number"]
    pr_title = original_pr.get("title", "")
    merge_commit_sha = original_pr.get("merge_commit_sha", bad_commit)
    logger.info(
        "Found PR #%d: %s (merge: %s)",
        pr_number, pr_title, merge_commit_sha[:12])

    # Check if already reverted — looks for actual PRs, not just branches.
    if check_already_reverted(
            owner, repo, pr_number, bad_commit[:7], branch, token):
        return {
            "status": "skipped", "reason": "already_reverted",
            "original_pr": pr_number}

    # Validate the commit.
    commit_data = _get_commit(owner, repo, merge_commit_sha, token)
    if not commit_data:
        return {"status": "failed", "reason": "cannot_fetch_commit"}

    if _is_submodule_bump(commit_data):
        logger.info("PR #%d is a submodule bump, skipping", pr_number)
        return {
            "status": "skipped", "reason": "submodule_bump",
            "original_pr": pr_number}

    file_count = len(commit_data.get("files", []))
    if file_count > MAX_FILES_FOR_AUTO_REVERT:
        logger.info(
            "PR #%d has %d files (max %d), skipping",
            pr_number, file_count, MAX_FILES_FOR_AUTO_REVERT)
        return {
            "status": "skipped", "reason": "too_many_files",
            "original_pr": pr_number, "file_count": file_count}

    # Build revert commit message.
    revert_branch = _revert_branch_name(bad_commit[:7])
    revert_message = (
        f'Revert "{pr_title}" (#{pr_number})\n\n'
        f"This reverts commit {merge_commit_sha}.\n\n"
        f"Auto-reverted by PR binary search analyzer.\n"
        f"Original PR: {original_pr.get('html_url', '')}")

    # Clone, revert, push.
    revert_sha = _clone_and_revert(
        owner, repo, branch, merge_commit_sha,
        revert_branch, revert_message, token)
    if not revert_sha:
        return {
            "status": "skipped", "reason": "revert_conflict",
            "original_pr": pr_number}

    # Build PR body with binary search context.
    test_details = ""
    if metadata:
        test_details = (
            f"\n\n**Binary search details:**\n"
            f"- Checker: `{metadata.get('CheckerType', 'N/A')}`\n"
            f"- Test file: `{metadata.get('FilePath', 'N/A')}`\n"
            f"- Test case: `{metadata.get('TestCase', 'N/A')}`\n"
            f"- Analyzer run: `{metadata.get('AnalyzerRunId', 'N/A')}`\n")

    pr_title_revert = f'Revert "{pr_title}" (#{pr_number})'
    pr_body = (
        f"This reverts #{pr_number} (commit {merge_commit_sha}).\n\n"
        f"The PR binary search analyzer identified this commit as the "
        f"root cause of test regression(s).{test_details}\n\n"
        f"---\n"
        f"*Auto-generated by PR binary search analyzer.*")

    pr_url = _open_pull_request(
        owner, repo, revert_branch, branch,
        pr_title_revert, pr_body, token)
    if pr_url:
        logger.info("Revert PR created: %s", pr_url)
        return {
            "status": "created",
            "revert_pr_url": pr_url,
            "original_pr": pr_number,
            "revert_commit": revert_sha,
        }

    return {"status": "failed", "reason": "cannot_create_pr"}


def process_results(rows, token, dry_run=False):
    """Process Kusto result rows and create revert PRs.

    Deduplicates by (SourceRepo, BadCommit) so each commit is reverted once
    even if it caused multiple test failures.
    """
    seen_commits = set()
    results = []

    for row in rows:
        bad_commit = row.get("BadCommit", "")
        source_repo = row.get("SourceRepo", "")
        branch = row.get("Branch", "master")

        if not bad_commit or not source_repo:
            continue

        dedup_key = f"{source_repo}:{bad_commit}"
        if dedup_key in seen_commits:
            logger.info("Skipping duplicate commit %s", bad_commit[:12])
            continue
        seen_commits.add(dedup_key)

        if not REPO_FORMAT_RE.match(source_repo):
            logger.warning("Invalid repo format: %s", source_repo)
            continue
        owner, repo = source_repo.split("/")

        if dry_run:
            logger.info(
                "[DRY RUN] Would create revert PR for %s/%s commit %s",
                owner, repo, bad_commit[:12])
            results.append({"commit": bad_commit, "status": "dry_run"})
            continue

        try:
            info = create_revert_pr(
                owner, repo, branch, bad_commit, row, token)
            results.append({"commit": bad_commit, **info})
        except Exception as e:
            logger.error(
                "Failed to process %s: %s",
                bad_commit[:12], e, exc_info=True)
            results.append({
                "commit": bad_commit,
                "status": "error", "reason": str(e)})

    return results


# ── CLI ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Create revert PRs for bad commits found by "
                    "PR binary search.",
    )
    parser.add_argument(
        "--lookback_hours", type=int, default=48,
        help="How far back to look in PRBinarySearchResult (default: 48)")
    parser.add_argument(
        "--source_repo", type=str, default="sonic-net/sonic-buildimage",
        help="Only process results from this repo "
             "(default: sonic-net/sonic-buildimage)")
    parser.add_argument(
        "--allowed_repos", type=str, default="",
        help="Comma-separated list of repos eligible for auto-revert. "
             "Overrides the built-in REVERT_ALLOWED_REPOS set when provided.")
    parser.add_argument(
        "--dry_run", type=parse_bool_arg, default=False,
        help="Log what would be done without creating PRs")
    args = parser.parse_args()

    # Validate source_repo early.
    if args.source_repo:
        _validate_repo_format(args.source_repo)

    # Allow overriding the allowed-repos set at runtime.
    if args.allowed_repos:
        repos = [r.strip() for r in args.allowed_repos.split(",") if r.strip()]
        for r in repos:
            _validate_repo_format(r)
        REVERT_ALLOWED_REPOS.clear()
        REVERT_ALLOWED_REPOS.update(repos)
        logger.info("Allowed repos overridden: %s", REVERT_ALLOWED_REPOS)

    # Kusto auth — same pattern as other scripts in this directory.
    access_token = os.environ.get("ACCESS_TOKEN")
    kusto_ingest_url = os.environ.get("KUSTO_CLUSTER_INGEST_URL", "")
    # Prefer an explicit query-endpoint env var; fall back to deriving it from
    # the ingest URL (e.g. https://ingest-foo.kusto.windows.net →
    # https://foo.kusto.windows.net).  The derivation only works when the URL
    # follows the standard "ingest-" prefix convention.
    kusto_query_url = os.environ.get("KUSTO_CLUSTER_URL", "")
    if not kusto_query_url:
        if "//ingest-" in kusto_ingest_url:
            kusto_query_url = kusto_ingest_url.replace("//ingest-", "//", 1)
        else:
            logger.error(
                "Cannot derive Kusto query URL from KUSTO_CLUSTER_INGEST_URL "
                "(%r). Set KUSTO_CLUSTER_URL explicitly.", kusto_ingest_url)
            sys.exit(1)

    if not access_token or not kusto_ingest_url:
        logger.error(
            "ACCESS_TOKEN and KUSTO_CLUSTER_INGEST_URL env vars required")
        sys.exit(1)

    github_token = os.environ.get("GIT_API_TOKEN", "")
    if not github_token and not args.dry_run:
        logger.error(
            "GIT_API_TOKEN env var is required (needs repo write access)")
        sys.exit(1)

    kcsb = KustoConnectionStringBuilder \
        .with_aad_application_token_authentication(
            kusto_query_url, access_token)
    kusto_client = KustoClient(kcsb)

    # Fetch bad commits from Kusto.
    logger.info(
        "Fetching bad_commit results from Kusto (last %dh, repo=%s)",
        args.lookback_hours, args.source_repo or "all")
    rows = fetch_bad_commit_results(
        kusto_client, args.lookback_hours, source_repo=args.source_repo)
    logger.info("Found %d bad_commit results", len(rows))

    if not rows:
        logger.info("No bad commits to revert")
        return

    # Process and create revert PRs.
    results = process_results(rows, github_token, dry_run=args.dry_run)

    # Summary.
    created = [r for r in results if r.get("status") == "created"]
    skipped = [r for r in results if r.get("status") == "skipped"]
    failed = [r for r in results
              if r.get("status") in ("failed", "error")]

    logger.info(
        "Summary: %d created, %d skipped, %d failed",
        len(created), len(skipped), len(failed))
    for r in results:
        logger.info(
            "  %s: %s",
            r.get("commit", "?")[:12], json.dumps(r, default=str))


if __name__ == "__main__":
    main()
