import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import yaml

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SkipExpiryConfig:
    """Configuration used by the skip-expiry workflow."""

    maintainers: List[str]
    expiry_days: int
    release_includes: List[str] = field(default_factory=list)
    release_excludes: List[str] = field(default_factory=list)


def load_skip_expiry_config(config_path: Path) -> SkipExpiryConfig:
    """Load and validate skip-expiry workflow configuration."""
    logger.info("Loading skip-expiry config from %s", config_path)

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as file_obj:
        content = yaml.safe_load(file_obj) or {}

    maintainers = content.get("maintainers")
    if not isinstance(maintainers, list) or not maintainers:
        raise ValueError(
            "Fatal configuration error: 'maintainers' list is missing or empty in SKIP_EXPIRY_CONFIG.yaml"
        )

    normalized_maintainers = [str(item).strip().lstrip("@") for item in maintainers if str(item).strip()]
    if not normalized_maintainers:
        raise ValueError(
            "Fatal configuration error: no valid maintainer usernames found in 'maintainers' list"
        )

    expiry_days_raw = (content.get("expiry") or {}).get("default_days", 90)
    try:
        expiry_days = int(expiry_days_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("expiry.default_days must be an integer") from exc

    if expiry_days <= 0:
        raise ValueError("expiry.default_days must be greater than zero")

    releases = content.get("releases") or {}
    if releases is None:
        releases = {}
    if not isinstance(releases, dict):
        raise ValueError("releases must be a mapping")

    release_includes = releases.get("includes") or []
    if not isinstance(release_includes, list):
        raise ValueError("releases.includes must be a list")

    normalized_release_includes = [str(item).strip() for item in release_includes if str(item).strip()]
    for pattern in normalized_release_includes:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid regex in releases.includes: {pattern}") from exc

    release_excludes = releases.get("excludes") or []
    if not isinstance(release_excludes, list):
        raise ValueError("releases.excludes must be a list")

    normalized_release_excludes = [str(item).strip() for item in release_excludes if str(item).strip()]

    logger.info(
        "Loaded skip-expiry config: %d maintainers, expiry.default_days=%d, includes=%d, excludes=%d",
        len(normalized_maintainers),
        expiry_days,
        len(normalized_release_includes),
        len(normalized_release_excludes),
    )
    return SkipExpiryConfig(
        maintainers=normalized_maintainers,
        expiry_days=expiry_days,
        release_includes=normalized_release_includes,
        release_excludes=normalized_release_excludes,
    )
