import logging
import re
from pathlib import Path
from typing import Dict, Iterable, Set

import yaml

from .models import IssueRef

logger = logging.getLogger(__name__)

CONDITIONAL_MARK_GLOB_PATTERNS = (
    "tests_mark_conditions*.yaml",
    "tests_mark_conditions*.yml",
)

ISSUE_URL_PATTERN = re.compile(
    r"https?://github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+)/issues/(?P<number>\d+)",
    flags=re.IGNORECASE,
)


def _extract_issue_refs_from_text(raw_text: str) -> Set[IssueRef]:
    refs: Set[IssueRef] = set()
    for match in ISSUE_URL_PATTERN.finditer(raw_text):
        refs.add(
            IssueRef(
                owner=match.group("owner").strip(),
                repo=match.group("repo").strip(),
                number=int(match.group("number")),
            )
        )
    return refs


def _iter_conditions(raw_conditions: object) -> Iterable[str]:
    if isinstance(raw_conditions, str):
        yield raw_conditions
    elif isinstance(raw_conditions, list):
        for item in raw_conditions:
            if isinstance(item, str):
                yield item


def _extract_issue_refs_from_entry(entry: Dict[str, object]) -> Set[IssueRef]:
    refs: Set[IssueRef] = set()
    for mark_type in ("skip", "xfail"):
        mark_config = entry.get(mark_type)
        if not isinstance(mark_config, dict):
            continue

        for condition_text in _iter_conditions(mark_config.get("conditions")):
            refs.update(_extract_issue_refs_from_text(condition_text))
    return refs


def collect_github_issues_from_conditional_marks(conditional_mark_dir: Path) -> Set[IssueRef]:
    """Scan conditional mark files and return unique GitHub issue references."""
    issue_refs: Set[IssueRef] = set()
    files = []
    for pattern in CONDITIONAL_MARK_GLOB_PATTERNS:
        files.extend(sorted(conditional_mark_dir.glob(pattern)))

    files = sorted(set(files))
    if not files:
        logger.warning("No conditional mark files found under %s", conditional_mark_dir)
        return issue_refs

    logger.info("Found %d conditional mark files", len(files))

    for mark_file in files:
        try:
            with mark_file.open("r", encoding="utf-8") as file_obj:
                payload = yaml.safe_load(file_obj) or {}
        except Exception as exc:  # pragma: no cover - runtime protection
            logger.exception("Failed to parse %s: %s", mark_file, exc)
            continue

        if not isinstance(payload, dict):
            logger.warning("Ignoring non-dict YAML root in %s", mark_file)
            continue

        file_ref_count_before = len(issue_refs)
        for _, entry in payload.items():
            if isinstance(entry, dict):
                issue_refs.update(_extract_issue_refs_from_entry(entry))

        logger.info(
            "Parsed %s and discovered %d issue(s)",
            mark_file,
            len(issue_refs) - file_ref_count_before,
        )

    logger.info("Collected %d unique GitHub issue(s) from conditional marks", len(issue_refs))
    return issue_refs
