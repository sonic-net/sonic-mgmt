import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import logging
import os
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .reporting import TestReportData, create_reporter_from_env

from .conditional_marks import collect_report_entries_from_conditional_marks
from .config import load_skip_expiry_config
from .expiry import IssueEvaluation, SkipExpiryManager
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


def _parse_github_timestamp(raw_ts: object) -> Optional[datetime]:
    if not isinstance(raw_ts, str) or not raw_ts:
        return None
    try:
        return datetime.fromisoformat(raw_ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _truncate_timestamp_to_date(timestamp_str: Optional[str]) -> Optional[str]:
    """Convert ISO-8601 timestamp to YYYY-MM-DD format for GraphQL Date scalar.

    GitHub's GraphQL Date scalar only accepts YYYY-MM-DD format.
    Strips time portion and timezone from ISO-8601 timestamps.
    """
    if not timestamp_str or not isinstance(timestamp_str, str):
        return None
    # Extract date portion (everything before 'T')
    date_part = timestamp_str.split("T")[0]
    return date_part if date_part else None


def _compute_days_delta(target: Optional[datetime], now: datetime) -> Optional[int]:
    if target is None:
        return None
    return int((target - now).total_seconds() // 86400)


def _expiry_bucket(days_to_expiry: Optional[int], current_status: str) -> str:
    if current_status == "expired":
        return "expired"
    if days_to_expiry is None:
        return "unknown"
    if days_to_expiry < 0:
        return "expired"
    if days_to_expiry <= 1:
        return "0-1d"
    if days_to_expiry <= 7:
        return "1-7d"
    if days_to_expiry <= 15:
        return "7-15d"
    if days_to_expiry <= 30:
        return "15-30d"
    return ">30"


def _normalize_condition_file(condition_file: str, repo_root: Path) -> str:
    raw = Path(condition_file)
    try:
        return str(raw.resolve().relative_to(repo_root))
    except Exception:
        return condition_file


def _build_report_row(
    entry: Dict[str, Any],
    issue_ref: Optional[IssueRef],
    evaluation: Optional[IssueEvaluation],
    source_repo: str,
    warning_days: int,
    default_maintainer: str,
    maintainer_map: Dict[str, str],
    repo_root: Path,
    now: datetime,
) -> TestReportData:
    test_id = str(entry.get("test_id") or "").strip()
    test_category = str(entry.get("test_category") or "unknown").strip().lower()
    is_cross_repo = bool(issue_ref and f"{issue_ref.owner}/{issue_ref.repo}".lower() != source_repo.lower())

    issue_payload = evaluation.issue_payload if evaluation else {}
    issue_state = str(issue_payload.get("state") or "").lower() if issue_payload else ""
    current_status = "unknown"
    if bool(entry.get("no_issue_linked")):
        current_status = "no_issue_linked"
    elif issue_state == "closed":
        current_status = "skip_closed"
    elif evaluation and evaluation.expired_now:
        current_status = "expired"
    elif issue_state == "open":
        current_status = "not expired"

    issue_created_at_raw = issue_payload.get("created_at") if issue_payload else None
    issue_closed_at_raw = issue_payload.get("closed_at") if issue_payload else None
    issue_updated_at_raw = issue_payload.get("updated_at") if issue_payload else None

    issue_created_at = _parse_github_timestamp(issue_created_at_raw)
    age_days = _compute_days_delta(issue_created_at, now)
    if age_days is not None:
        age_days = max(0, -age_days)

    days_to_expiry = _compute_days_delta(evaluation.expiry_at if evaluation else None, now)
    expiry_date = evaluation.expiry_at.date().isoformat() if evaluation and evaluation.expiry_at else ""
    expiry_bucket = _expiry_bucket(days_to_expiry, current_status)

    issue_assignees: List[str] = []
    for assignee in issue_payload.get("assignees") or []:
        if isinstance(assignee, dict):
            login = str(assignee.get("login") or "").strip()
            if login:
                issue_assignees.append(login)

    issue_author = ""
    if isinstance(issue_payload.get("user"), dict):
        issue_author = str((issue_payload.get("user") or {}).get("login") or "").strip()

    maintainer = maintainer_map.get(test_category) or default_maintainer

    last_comment_ts = None
    if evaluation:
        for comment in evaluation.comments:
            comment_ts = _parse_github_timestamp(comment.get("updated_at") or comment.get("created_at"))
            if comment_ts and (last_comment_ts is None or comment_ts > last_comment_ts):
                last_comment_ts = comment_ts

    last_updated_ts = _parse_github_timestamp(issue_updated_at_raw)
    activity_candidates = [ts for ts in (last_updated_ts, last_comment_ts) if ts is not None]
    latest_activity = max(activity_candidates) if activity_candidates else None
    days_since_last_activity = None
    if latest_activity is not None:
        days_since_last_activity = max(0, int((now - latest_activity).total_seconds() // 86400))

    no_issue_linked = bool(entry.get("no_issue_linked") or issue_ref is None)
    is_permanent_skip = bool(entry.get("is_permanent_skip") or no_issue_linked)
    needs_cleanup = bool(issue_ref is not None and issue_state == "closed")
    needs_attention = bool(issue_state == "open" and current_status == "expired")
    approaching_expiry = bool(days_to_expiry is not None and 0 <= days_to_expiry <= warning_days)

    owner = issue_assignees[0] if issue_assignees else maintainer
    issue_url = issue_ref.html_url if issue_ref else ""
    repository = f"{issue_ref.owner}/{issue_ref.repo}" if issue_ref else ""

    return TestReportData(
        test_id=test_id,
        title=_derive_title_from_test_id(test_id),
        expiry_date=expiry_date,
        current_status=current_status,
        issue_url=issue_url,
        owner=owner,
        fields={
            "issue_number": issue_ref.number if issue_ref else None,
            "issue_repository": repository,
            "issue_state": issue_state or None,
            "issue_created_at": _truncate_timestamp_to_date(issue_created_at_raw),
            "issue_closed_at": _truncate_timestamp_to_date(issue_closed_at_raw),
            "age_days": age_days,
            "days_to_expiry": days_to_expiry,
            "expiry_bucket": expiry_bucket,
            "maintainer": maintainer,
            "issue_assignees": ", ".join(issue_assignees),
            "issue_author": issue_author,
            "condition_file": _normalize_condition_file(str(entry.get("condition_file") or ""), repo_root),
            "test_category": test_category,
            "is_permanent_skip": is_permanent_skip,
            "last_updated_at": _truncate_timestamp_to_date(issue_updated_at_raw),
            "last_comment_at": _truncate_timestamp_to_date(last_comment_ts.isoformat() if last_comment_ts else None),
            "days_since_last_activity": days_since_last_activity,
            "is_cross_repo": is_cross_repo,
            "source_repo": source_repo,
            "needs_cleanup": needs_cleanup,
            "needs_attention": needs_attention,
            "approaching_expiry": approaching_expiry,
            "no_issue_linked": no_issue_linked,
        },
    )


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

    report_entries = collect_report_entries_from_conditional_marks(conditional_mark_dir)
    all_issues = sorted({entry["issue_ref"] for entry in report_entries if entry.get("issue_ref") is not None})
    issues, skipped_issues = _filter_same_repo_issues(all_issues, args.target_repo)
    logging.getLogger(__name__).info(
        "Evaluating %d same-repo issue(s) from %d total reference(s) for target %s",
        len(issues),
        len(all_issues),
        args.target_repo,
    )
    if skipped_issues:
        logging.getLogger(__name__).warning(
            "Skipping mutation for %d cross-repo issue(s); they are still included in reporting",
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
    issue_evaluations: Dict[IssueRef, Optional[IssueEvaluation]] = {}
    source_repo = f"{_normalize_repo_name(args.target_repo)[0]}/{_normalize_repo_name(args.target_repo)[1]}"
    now = datetime.now(timezone.utc)
    default_maintainer = config.maintainers[0] if config.maintainers else ""

    for issue_ref in issues:
        try:
            evaluation = manager.process_issue(issue_ref)
            issue_evaluations[issue_ref] = evaluation
        except Exception:  # pragma: no cover - runtime protection
            had_errors = True
            issue_evaluations[issue_ref] = None
            logging.getLogger(__name__).exception("Failed to process %s", issue_ref.html_url)

    if reporter:
        for issue_ref in skipped_issues:
            try:
                issue_evaluations[issue_ref] = manager.evaluate_issue(issue_ref)
            except Exception:  # pragma: no cover - runtime protection
                issue_evaluations[issue_ref] = None
                had_errors = True
                logging.getLogger(__name__).exception("Failed to evaluate cross-repo issue %s", issue_ref.html_url)

        for entry in report_entries:
            test_id = str(entry.get("test_id") or "").strip()
            if not test_id:
                logging.getLogger(__name__).info("Skipping project upsert for row with missing test_id")
                continue

            issue_ref = entry.get("issue_ref")
            evaluation = issue_evaluations.get(issue_ref) if isinstance(issue_ref, IssueRef) else None
            row = _build_report_row(
                entry=entry,
                issue_ref=issue_ref if isinstance(issue_ref, IssueRef) else None,
                evaluation=evaluation,
                source_repo=source_repo,
                warning_days=config.warning_days,
                default_maintainer=default_maintainer,
                maintainer_map=config.maintainer_map,
                repo_root=repo_root,
                now=now,
            )

            with _reporting_auth_env(reporting_token):
                reporter.upsert_project_item(row)

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
