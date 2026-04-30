import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List

import yaml

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SkipExpiryConfig:
    """Configuration used by the skip-expiry workflow."""

    maintainers: List[str]
    expiry_days: int


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

    logger.info(
        "Loaded skip-expiry config: %d maintainers, expiry.default_days=%d",
        len(normalized_maintainers),
        expiry_days,
    )
    return SkipExpiryConfig(maintainers=normalized_maintainers, expiry_days=expiry_days)
