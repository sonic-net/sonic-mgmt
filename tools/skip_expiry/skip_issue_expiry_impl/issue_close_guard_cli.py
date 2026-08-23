import argparse
import logging
import os
from pathlib import Path

from .config import load_skip_expiry_config
from .github_api import GitHubApiClient
from .issue_close_guard import normalize_repo_name, run_issue_close_guard

DEFAULT_TARGET_REPO = "sonic-net/sonic-mgmt"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Conditional-mark issue close guard runner")
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
        "--event-path",
        default=os.getenv("GITHUB_EVENT_PATH", ""),
        help="Path to GitHub event JSON payload (defaults to GITHUB_EVENT_PATH)",
    )
    parser.add_argument(
        "--target-repo",
        default=os.getenv("GITHUB_REPOSITORY", DEFAULT_TARGET_REPO),
        help="Target repository in owner/repo format",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
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

    logger = logging.getLogger(__name__)

    repo_root = Path(args.repo_root).resolve()
    config_path = _resolve_path(repo_root, args.config)
    conditional_mark_dir = args.conditional_mark_dir

    if not args.event_path:
        logger.fatal("Event payload path is required (--event-path or GITHUB_EVENT_PATH)")
        return 2

    event_path = _resolve_path(repo_root, args.event_path)

    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        logger.fatal("GITHUB_TOKEN is required")
        return 2

    try:
        normalize_repo_name(args.target_repo)
    except ValueError:
        logger.fatal("Invalid --target-repo value: %s", args.target_repo)
        return 2

    if not event_path.exists():
        logger.fatal("Event payload file not found: %s", event_path)
        return 2

    try:
        config = load_skip_expiry_config(config_path)
    except Exception:
        logger.exception("Failed to load workflow configuration")
        return 2

    api_client = GitHubApiClient(token=token)

    try:
        action_taken = run_issue_close_guard(
            api_client=api_client,
            config=config,
            repo_root=repo_root,
            conditional_mark_dir=conditional_mark_dir,
            target_repo=args.target_repo,
            event_path=event_path,
        )
    except Exception:
        logger.exception("Issue close guard run failed")
        return 1

    if action_taken:
        logger.info("Issue close guard reopened a tracked issue")
    else:
        logger.info("Issue close guard completed with no reopen action")

    return 0
