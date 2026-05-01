import argparse
from contextlib import contextmanager
import logging
import os
from pathlib import Path
from typing import Iterator, List, Tuple

from reporting import TestReportData, create_reporter_from_env

from .conditional_marks import collect_issue_test_mapping_from_conditional_marks
from .config import load_skip_expiry_config
from .expiry import SkipExpiryManager
from .github_api import GitHubApiClient
from .models import IssueRef

DEFAULT_TARGET_REPO = "sonic-net/sonic-mgmt"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Skip-expiry issue workflow runner")
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root containing tests/common/plugins/conditional_mark and .github/SKIP_EXPIRY_CONFIG.yaml",
    )
    parser.add_argument(
        "--config",
        default=".github/SKIP_EXPIRY_CONFIG.yaml",
        help="Path to skip expiry config YAML, relative to --repo-root if not absolute",
    )
    parser.add_argument(
        "--conditional-mark-dir",
        default="tests/common/plugins/conditional_mark",
        help="Path to conditional mark directory, relative to --repo-root if not absolute",
    )
    parser.add_argument(
        "--log-level",
        default="DEBUG",
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
    )
    parser.add_argument(
        "--no-op",
        action="store_true",
        help="Evaluate issues and log planned actions without mutating GitHub state",
    )
    parser.add_argument(
        "--target-repo",
        default=os.getenv("GITHUB_REPOSITORY", DEFAULT_TARGET_REPO),
        help="Only manage issues from this repository (owner/repo), defaults to GITHUB_REPOSITORY",
    )
    return parser.parse_args()


def _resolve_path(repo_root: Path, candidate: str) -> Path:
    raw = Path(candidate)
    if raw.is_absolute():
        return raw
    return repo_root / raw


def _normalize_repo_name(raw_repo: str) -> Tuple[str, str]:
    candidate = (raw_repo or "").strip().lower()
    owner, separator, repo = candidate.partition("/")
    if separator != "/" or not owner or not repo:
        raise ValueError("Repository must be in 'owner/repo' format")
    return owner, repo


def _filter_same_repo_issues(issues: List[IssueRef], target_repo: str) -> Tuple[List[IssueRef], List[IssueRef]]:
    owner, repo = _normalize_repo_name(target_repo)
    included: List[IssueRef] = []
    skipped: List[IssueRef] = []
    for issue in issues:
        if issue.owner.lower() == owner and issue.repo.lower() == repo:
            included.append(issue)
        else:
            skipped.append(issue)
    return included, skipped


def _derive_title_from_test_id(test_id: str) -> str:
    normalized = (test_id or "").strip()
    if not normalized:
        return "Unnamed test"

    if "::" in normalized:
        return normalized.split("::")[-1]

    return normalized


def _resolve_reporting_token() -> str:
    for env_var in ("GITHUB_APP_TOKEN", "GH_APP_TOKEN"):
        token = os.getenv(env_var, "").strip()
        if token:
            return token
    return ""


@contextmanager
def _reporting_auth_env(reporting_token: str) -> Iterator[None]:
    if not reporting_token:
        yield
        return

    original_github_token = os.environ.get("GITHUB_TOKEN")
    os.environ["GITHUB_TOKEN"] = reporting_token
    try:
        yield
    finally:
        if original_github_token is None:
            os.environ.pop("GITHUB_TOKEN", None)
        else:
            os.environ["GITHUB_TOKEN"] = original_github_token


def run() -> int:
    args = _parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    repo_root = Path(args.repo_root).resolve()
    config_path = _resolve_path(repo_root, args.config)
    conditional_mark_dir = _resolve_path(repo_root, args.conditional_mark_dir)

    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        logging.getLogger(__name__).fatal("GITHUB_TOKEN is required")
        return 2

    reporting_requested = bool(os.getenv("PROJECT_ID", "").strip())
    reporting_token = _resolve_reporting_token()
    if reporting_requested and not reporting_token:
        logging.getLogger(__name__).fatal(
            "GITHUB_APP_TOKEN or GH_APP_TOKEN is required when PROJECT_ID is set"
        )
        return 2

    bot_login = os.getenv("SKIP_EXPIRY_BOT_LOGIN", "github-actions[bot]").strip()
    if not bot_login:
        logging.getLogger(__name__).fatal("SKIP_EXPIRY_BOT_LOGIN is empty")
        return 2

    try:
        config = load_skip_expiry_config(config_path)
    except Exception:
        logging.getLogger(__name__).exception("Failed to load workflow configuration")
        return 2

    if not conditional_mark_dir.exists():
        logging.getLogger(__name__).fatal("Conditional mark directory not found: %s", conditional_mark_dir)
        return 2

    try:
        _normalize_repo_name(args.target_repo)
    except ValueError:
        logging.getLogger(__name__).fatal("Invalid --target-repo value: %s", args.target_repo)
        return 2

    issue_test_mapping = collect_issue_test_mapping_from_conditional_marks(conditional_mark_dir)
    all_issues = sorted(issue_test_mapping.keys())
    issues, skipped_issues = _filter_same_repo_issues(all_issues, args.target_repo)
    logging.getLogger(__name__).info(
        "Evaluating %d same-repo issue(s) from %d total reference(s) for target %s",
        len(issues),
        len(all_issues),
        args.target_repo,
    )
    if skipped_issues:
        logging.getLogger(__name__).warning(
            "Skipping %d cross-repo issue(s); workflow account may not have write access outside %s",
            len(skipped_issues),
            args.target_repo,
        )
    if args.no_op:
        logging.getLogger(__name__).info("NO-OP mode enabled: no labels/comments will be changed")

    api_client = GitHubApiClient(token=token)
    manager = SkipExpiryManager(
        api_client=api_client,
        config=config,
        bot_login=bot_login,
        no_op=args.no_op,
    )
    with _reporting_auth_env(reporting_token):
        reporter = create_reporter_from_env()
    if reporter:
        logging.getLogger(__name__).info("Project V2 reporting is enabled")
    else:
        logging.getLogger(__name__).info("Project V2 reporting is disabled")

    had_errors = False
    for issue_ref in issues:
        try:
            evaluation = manager.process_issue(issue_ref)
            if reporter and evaluation:
                assignees = evaluation.issue_payload.get("assignees") or []
                owner = ""
                if isinstance(assignees, list) and assignees:
                    first_assignee = assignees[0]
                    if isinstance(first_assignee, dict):
                        owner = str(first_assignee.get("login") or "").strip()

                status_text = "expired" if evaluation.expired_now else "active"
                expiry_date = evaluation.expiry_at.date().isoformat()
                for test_mark in issue_test_mapping.get(issue_ref, []):
                    test_id = str(test_mark.get("test_id") or "").strip()
                    if not test_id:
                        logging.getLogger(__name__).info(
                            "Skipping project upsert for issue %s due to missing test_id",
                            issue_ref.html_url,
                        )
                        continue

                    with _reporting_auth_env(reporting_token):
                        reporter.upsert_project_item(
                            TestReportData(
                                test_id=test_id,
                                title=_derive_title_from_test_id(test_id),
                                expiry_date=expiry_date,
                                current_status=status_text,
                                issue_url=issue_ref.html_url,
                                owner=owner,
                            )
                        )
        except Exception:  # pragma: no cover - runtime protection
            had_errors = True
            logging.getLogger(__name__).exception("Failed to process %s", issue_ref.html_url)

    if reporter:
        with _reporting_auth_env(reporting_token):
            summary = reporter.summary()
        logging.getLogger(__name__).info(
            "Project V2 reporting summary: created=%d updated=%d skipped=%d",
            summary["created"],
            summary["updated"],
            summary["skipped"],
        )

    if had_errors:
        logging.getLogger(__name__).error("Completed with one or more issue-processing errors")
        return 1

    logging.getLogger(__name__).info("Completed successfully")
    return 0
