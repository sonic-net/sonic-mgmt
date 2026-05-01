import logging
import re
from pathlib import Path
from typing import Dict, Iterable, List, Set

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


def _extract_test_issue_entries(test_id: str, entry: Dict[str, object]) -> List[Dict[str, object]]:
    entries: List[Dict[str, object]] = []
    for mark_type in ("skip", "xfail"):
        mark_config = entry.get(mark_type)
        if not isinstance(mark_config, dict):
            continue

        seen_refs: Set[IssueRef] = set()
        for condition_text in _iter_conditions(mark_config.get("conditions")):
            refs = _extract_issue_refs_from_text(condition_text)
            for ref in refs:
                if ref in seen_refs:
                    continue
                seen_refs.add(ref)
                entries.append({"test_id": test_id, "mark_type": mark_type, "issue_ref": ref})

    return entries


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


def collect_issue_test_mapping_from_conditional_marks(
        conditional_mark_dir: Path) -> Dict[IssueRef, List[Dict[str, str]]]:
    """Scan conditional mark files and map issue refs to affected test entries."""
    issue_to_tests: Dict[IssueRef, List[Dict[str, str]]] = {}
    files = []
    for pattern in CONDITIONAL_MARK_GLOB_PATTERNS:
        files.extend(sorted(conditional_mark_dir.glob(pattern)))

    files = sorted(set(files))
    if not files:
        logger.warning("No conditional mark files found under %s", conditional_mark_dir)
        return issue_to_tests

    logger.info("Found %d conditional mark files for issue-test mapping", len(files))

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

        mapped_entries = 0
        for test_id, entry in payload.items():
            if not isinstance(test_id, str) or not isinstance(entry, dict):
                continue

            for mapped in _extract_test_issue_entries(test_id, entry):
                issue_ref = mapped["issue_ref"]
                issue_to_tests.setdefault(issue_ref, []).append(
                    {
                        "test_id": mapped["test_id"],
                        "mark_type": mapped["mark_type"],
                    }
                )
                mapped_entries += 1

        logger.info("Parsed %s and mapped %d issue-linked test mark(s)", mark_file, mapped_entries)

    logger.info("Mapped %d unique issue(s) to test entries", len(issue_to_tests))
    return issue_to_tests
