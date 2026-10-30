import json
import logging
import re
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Callable, ContextManager, Iterable, Iterator, List, Set

from .conditional_marks import collect_github_issues_from_conditional_marks
from .config import SkipExpiryConfig
from .github_api import GitHubApiClient
from .models import IssueRef

logger = logging.getLogger(__name__)

MANUAL_CLOSE_COMMENT = (
    "This issue is referenced by conditional mark entries and cannot be closed manually. "
    "To close it, remove all references to this issue from conditional mark files/tests across all supported releases, "
    "then close the issue again."
)


def normalize_repo_name(raw_repo: str) -> str:
    candidate = (raw_repo or "").strip().lower()
    owner, separator, repo = candidate.partition("/")
    if separator != "/" or not owner or not repo:
        raise ValueError("Repository must be in 'owner/repo' format")
    return f"{owner}/{repo}"


def resolve_release_branches(
    all_branches: Iterable[str],
    include_patterns: Iterable[str],
    exclude_names: Iterable[str],
) -> List[str]:
    compiled_patterns = [re.compile(pattern) for pattern in include_patterns]
    excluded = {name.strip() for name in exclude_names if str(name).strip()}

    selected: Set[str] = set()
    for branch in all_branches:
        if not branch or branch in excluded:
            continue
        for pattern in compiled_patterns:
            if pattern.search(branch):
                selected.add(branch)
                break

    return sorted(selected)


def build_branches_to_scan(release_branches: Iterable[str]) -> List[str]:
    ordered: List[str] = ["master"]
    for branch in sorted(set(release_branches)):
        if branch != "master":
            ordered.append(branch)
    return ordered


def _fetch_branch(repo_root: Path, branch: str) -> None:
    # An explicit refspec: a shallow or single-branch clone's default one only maps the cloned branch.
    subprocess.run(
        ["git", "fetch", "origin", f"+refs/heads/{branch}:refs/remotes/origin/{branch}", "--depth", "1"],
        check=True,
        cwd=repo_root,
        capture_output=True,
        text=True,
    )


def _repo_relative_dir(repo_root: Path, conditional_mark_dir: str) -> str:
    raw = Path(conditional_mark_dir)
    if raw.is_absolute():
        raw = raw.resolve().relative_to(repo_root.resolve())
    return raw.as_posix().strip("/")


@contextmanager
def _export_branch_mark_dir(repo_root: Path, branch: str, conditional_mark_dir: str) -> Iterator[Path]:
    """Yield a temporary copy of `conditional_mark_dir` as it is on origin/<branch>.

    The files are read from git objects, so the caller's working tree and HEAD are never touched.
    """
    _fetch_branch(repo_root, branch)
    ref = f"refs/remotes/origin/{branch}"
    rel_dir = _repo_relative_dir(repo_root, conditional_mark_dir)
    listing = subprocess.run(
        ["git", "ls-tree", "-z", ref, "--", f"{rel_dir}/"],
        check=True,
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    with tempfile.TemporaryDirectory(prefix="skip-expiry-") as tmp:
        export_dir = Path(tmp)
        for record in listing.stdout.split("\0"):
            if not record:
                continue
            # "<mode> <type> <object>\t<path>"; the glob is not recursive, so only this directory's files matter.
            meta, _, path = record.partition("\t")
            _, object_type, object_id = meta.split()
            if object_type != "blob":
                continue
            blob = subprocess.run(
                ["git", "cat-file", "blob", object_id],
                check=True,
                cwd=repo_root,
                capture_output=True,
            )
            (export_dir / PurePosixPath(path).name).write_bytes(blob.stdout)
        yield export_dir


def collect_issues_from_branches(
    repo_root: Path,
    conditional_mark_dir: str,
    branches: Iterable[str],
    export_branch: Callable[[Path, str, str], ContextManager[Path]] = _export_branch_mark_dir,
) -> Set[IssueRef]:
    """Issues referenced by the conditional marks on each of `branches`, read without checking anything out.

    A mark file that fails to parse on any branch raises, so the caller treats the scan as failed rather than
    acting on a partial set.
    """
    branch_list = list(branches)
    issues: Set[IssueRef] = set()
    for branch in branch_list:
        logger.info("Scanning conditional marks on branch %s", branch)
        with export_branch(repo_root, branch, conditional_mark_dir) as branch_dir:
            issues.update(collect_github_issues_from_conditional_marks(branch_dir, strict=True))
    logger.info("Collected %d unique issue(s) from %d branch(es)", len(issues), len(branch_list))
    return issues


def load_closed_issue_from_event(event_path: Path, target_repo: str) -> IssueRef:
    with event_path.open("r", encoding="utf-8") as file_obj:
        payload = json.load(file_obj)

    action = (payload.get("action") or "").strip().lower()
    if action != "closed":
        raise ValueError(f"Unsupported issue event action: {action}")

    event_repo_full_name = (((payload.get("repository") or {}).get("full_name")) or "").strip()
    if normalize_repo_name(event_repo_full_name) != normalize_repo_name(target_repo):
        raise ValueError(
            f"Event repository '{event_repo_full_name}' does not match target repository '{target_repo}'"
        )

    issue_number_raw = ((payload.get("issue") or {}).get("number"))
    try:
        issue_number = int(issue_number_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("Issue number is missing or invalid in event payload") from exc

    owner, _, repo = normalize_repo_name(target_repo).partition("/")
    return IssueRef(owner=owner, repo=repo, number=issue_number)


def enforce_issue_close_guard(
    api_client: GitHubApiClient,
    issue: IssueRef,
    tracked_issues: Set[IssueRef],
) -> bool:
    if issue not in tracked_issues:
        logger.info("Closed issue %s is not conditionally tracked; no action", issue.html_url)
        return False

    api_client.reopen_issue(issue)
    api_client.create_comment(issue, MANUAL_CLOSE_COMMENT)
    logger.info("Reopened tracked issue %s and added guidance comment", issue.html_url)
    return True


def collect_tracked_issues(
    api_client: GitHubApiClient,
    config: SkipExpiryConfig,
    repo_root: Path,
    conditional_mark_dir: str,
    target_repo: str,
) -> Set[IssueRef]:
    """Issues in `target_repo` referenced by conditional marks on master or any configured release branch.

    Each branch is fetched into `repo_root` and read from git objects; the working tree is left untouched.
    """
    owner, _, repo = normalize_repo_name(target_repo).partition("/")
    all_branches = api_client.list_repo_branches(owner, repo)
    release_branches = resolve_release_branches(
        all_branches=all_branches,
        include_patterns=config.release_includes,
        exclude_names=config.release_excludes,
    )
    branches_to_scan = build_branches_to_scan(release_branches)
    tracked_issues = collect_issues_from_branches(
        repo_root=repo_root,
        conditional_mark_dir=conditional_mark_dir,
        branches=branches_to_scan,
    )

    normalized_target_repo = normalize_repo_name(target_repo)
    return {
        issue
        for issue in tracked_issues
        if normalize_repo_name(f"{issue.owner}/{issue.repo}") == normalized_target_repo
    }


def run_issue_close_guard(
    api_client: GitHubApiClient,
    config: SkipExpiryConfig,
    repo_root: Path,
    conditional_mark_dir: str,
    target_repo: str,
    event_path: Path,
) -> bool:
    same_repo_issues = collect_tracked_issues(
        api_client=api_client,
        config=config,
        repo_root=repo_root,
        conditional_mark_dir=conditional_mark_dir,
        target_repo=target_repo,
    )

    closed_issue = load_closed_issue_from_event(event_path, target_repo)
    return enforce_issue_close_guard(api_client, closed_issue, same_repo_issues)
