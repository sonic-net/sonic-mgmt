import argparse
import logging
import os
from pathlib import Path

from .conditional_marks import collect_github_issues_from_conditional_marks
from .config import load_skip_expiry_config
from .expiry import SkipExpiryManager
from .github_api import GitHubApiClient


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
    return parser.parse_args()


def _resolve_path(repo_root: Path, candidate: str) -> Path:
    raw = Path(candidate)
    if raw.is_absolute():
        return raw
    return repo_root / raw


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

    issues = sorted(collect_github_issues_from_conditional_marks(conditional_mark_dir))
    logging.getLogger(__name__).info("Evaluating %d referenced issue(s)", len(issues))
    if args.no_op:
        logging.getLogger(__name__).info("NO-OP mode enabled: no labels/comments will be changed")

    api_client = GitHubApiClient(token=token)
    manager = SkipExpiryManager(
        api_client=api_client,
        config=config,
        bot_login=bot_login,
        no_op=args.no_op,
    )

    had_errors = False
    for issue_ref in issues:
        try:
            manager.process_issue(issue_ref)
        except Exception:  # pragma: no cover - runtime protection
            had_errors = True
            logging.getLogger(__name__).exception("Failed to process %s", issue_ref.html_url)

    if had_errors:
        logging.getLogger(__name__).error("Completed with one or more issue-processing errors")
        return 1

    logging.getLogger(__name__).info("Completed successfully")
    return 0
