"""
Utility functions for parsing sairedis.rec log files on DPU/DUT hosts.

This module provides tools to analyze SAI object operations
from /var/log/swss/sairedis.rec (or per-ASIC sairedis.asic{N}.rec).

Default behavior preserves the original DASH callers: only create/remove/set
are collected from the single-ASIC path /var/log/swss/sairedis.rec.
Pass include_ops / rec_path to keep get/stats or target multi-ASIC files.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set

logger = logging.getLogger(__name__)

DEFAULT_REC_PATH = "/var/log/swss/sairedis.rec"

# Ops ignored by default (DASH create/remove/set analysis)
DEFAULT_EXCLUDE_OPS = frozenset(("get", "notify", "stats", "clearstats"))

OPERATION_MAP = {
    "c": "create",
    "C": "create",  # bulk create
    "r": "remove",
    "R": "remove",  # bulk remove
    "s": "set",
    "S": "set",     # bulk set
    "g": "get",
    "G": "get",     # bulk get
    "n": "notify",
    "a": "stats",
    "q": "clearstats",
}


@dataclass
class SaiObjectChange:
    """Represents a single SAI object change from sairedis.rec"""
    timestamp: str
    operation: str  # 'create', 'remove', 'set', 'get', 'stats', ...
    object_type: str
    object_id: str
    attributes: Dict[str, str] = field(default_factory=dict)
    raw_line: str = ""


@dataclass
class SaiRedisChanges:
    """Aggregated SAI changes since test start"""
    created: List[SaiObjectChange] = field(default_factory=list)
    removed: List[SaiObjectChange] = field(default_factory=list)
    edited: List[SaiObjectChange] = field(default_factory=list)
    queried: List[SaiObjectChange] = field(default_factory=list)   # get
    stats: List[SaiObjectChange] = field(default_factory=list)     # stats / clearstats

    def summary(self) -> Dict[str, int]:
        """Return a summary count of changes by object type"""
        summary = {
            "created": defaultdict(int),
            "removed": defaultdict(int),
            "edited": defaultdict(int),
            "queried": defaultdict(int),
            "stats": defaultdict(int),
        }
        for change in self.created:
            summary["created"][change.object_type] += 1
        for change in self.removed:
            summary["removed"][change.object_type] += 1
        for change in self.edited:
            summary["edited"][change.object_type] += 1
        for change in self.queried:
            summary["queried"][change.object_type] += 1
        for change in self.stats:
            summary["stats"][change.object_type] += 1
        return {k: dict(v) for k, v in summary.items()}


def iter_changes(changes: SaiRedisChanges) -> List[SaiObjectChange]:
    """Flat list of all collected SaiObjectChange records."""
    return (
        list(changes.created)
        + list(changes.removed)
        + list(changes.edited)
        + list(changes.queried)
        + list(changes.stats)
    )


def sairedis_rec_paths(host) -> List[str]:
    """Return sairedis.rec path(s) for a host (multi-ASIC aware)."""
    try:
        if getattr(host, "sonichost", None) and host.sonichost.is_multi_asic:
            return [
                f"/var/log/swss/sairedis.asic{i}.rec"
                for i in range(len(host.asics))
            ]
        if getattr(host, "is_multi_asic", False):
            asics = getattr(host, "asics", None) or []
            return [f"/var/log/swss/sairedis.asic{i}.rec" for i in range(len(asics))]
    except Exception as exc:  # pragma: no cover - best-effort host introspection
        logger.debug("sairedis_rec_paths fallback for %s: %s", getattr(host, "hostname", host), exc)
    return [DEFAULT_REC_PATH]


def get_sairedis_line_count(dpuhost, rec_path: str = DEFAULT_REC_PATH) -> int:
    result = dpuhost.shell(
        f"wc -l {rec_path} | awk '{{print $1}}'",
        module_ignore_errors=True,
    )
    if result["rc"] == 0 and result.get("stdout", "").strip().isdigit():
        return int(result["stdout"].strip())
    return 0


def parse_sairedis_changes(
    dpuhost,
    start_line: int = 0,
    rec_path: str = DEFAULT_REC_PATH,
    include_ops: Optional[Iterable[str]] = None,
) -> SaiRedisChanges:
    """
    Parse the sairedis.rec file on the host and return collected objects
    since the specified start line.

    Args:
        dpuhost: Host object with a .shell() method (DPU or DUT)
        start_line: Line number to start parsing from (0-based). Use
            get_sairedis_line_count() at the start of the test.
        rec_path: Path to the sairedis record file on the host.
        include_ops: If None (default), exclude get/notify/stats/clearstats
            (DASH-compatible). If provided, only those operation names are kept.

    Returns:
        SaiRedisChanges with created/removed/edited (and queried/stats when included).
    """
    if start_line > 0:
        cmd = f"tail -n +{start_line + 1} {rec_path}"
    else:
        cmd = f"cat {rec_path}"

    result = dpuhost.shell(cmd, module_ignore_errors=True)
    if result["rc"] != 0:
        logger.warning(
            "Failed to read %s: %s",
            rec_path,
            result.get("stderr", "Unknown error"),
        )
        return SaiRedisChanges()

    changes = parse_sairedis_text(result["stdout"], include_ops=include_ops)

    logger.info("Total SAI changes (%s): %s", rec_path, changes.summary())
    logger.info("Created objects: %s", len(changes.created))
    logger.info("Removed objects: %s", len(changes.removed))
    logger.info("Edited objects: %s", len(changes.edited))
    if changes.queried or changes.stats:
        logger.info("Queried objects: %s", len(changes.queried))
        logger.info("Stats objects: %s", len(changes.stats))

    for change in changes.created:
        logger.debug("Created: %s:%s", change.object_type, change.object_id)
    for change in changes.removed:
        logger.debug("Removed: %s:%s", change.object_type, change.object_id)
    for change in changes.edited:
        logger.debug("Edited: %s:%s", change.object_type, change.object_id)

    return changes


def parse_sairedis_text(
    text: str,
    include_ops: Optional[Iterable[str]] = None,
) -> SaiRedisChanges:
    """
    Pure parser: turn sairedis.rec text into SaiRedisChanges (no shell/DUT).

    include_ops semantics match parse_sairedis_changes.
    """
    changes = SaiRedisChanges()
    allowed = _normalize_include_ops(include_ops)

    for line in text.splitlines():
        line = line.strip()
        if not line or "SAI_OBJECT_TYPE" not in line:
            continue
        try:
            if "||" in line:
                _parse_bulk_operation(line, changes, allowed)
            else:
                _parse_single_operation(line, changes, allowed)
        except Exception as e:
            logger.debug("Failed to parse sairedis line: %s, error: %s", line, e)
            continue
    return changes


def _normalize_include_ops(include_ops: Optional[Iterable[str]]) -> Optional[Set[str]]:
    if include_ops is None:
        return None
    return {op.lower() for op in include_ops}


def _should_keep(operation: Optional[str], allowed: Optional[Set[str]]) -> bool:
    if not operation:
        return False
    if allowed is None:
        return operation not in DEFAULT_EXCLUDE_OPS
    return operation in allowed


def _append_change(changes: SaiRedisChanges, change: SaiObjectChange) -> None:
    if change.operation == "create":
        changes.created.append(change)
    elif change.operation == "remove":
        changes.removed.append(change)
    elif change.operation == "set":
        changes.edited.append(change)
    elif change.operation == "get":
        changes.queried.append(change)
    elif change.operation in ("stats", "clearstats"):
        changes.stats.append(change)


def _parse_attributes(parts: Sequence[str]) -> Dict[str, str]:
    attributes = {}
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            attributes[key] = value
        elif part and part.startswith("SAI_"):
            # get/stats often list counter/attr names without values
            attributes[part] = ""
    return attributes


def _parse_single_operation(
    line: str,
    changes: SaiRedisChanges,
    allowed: Optional[Set[str]],
):
    """Parse a single (non-bulk) sairedis operation"""
    parts = line.split("|")
    if len(parts) < 3:
        return

    timestamp = parts[0]
    op_char = parts[1]
    operation = OPERATION_MAP.get(op_char)

    if not _should_keep(operation, allowed):
        return

    obj_part = parts[2]
    if ":" in obj_part:
        object_type, object_id = obj_part.split(":", 1)
    else:
        object_type = obj_part
        object_id = ""

    attributes = _parse_attributes(parts[3:])

    change = SaiObjectChange(
        timestamp=timestamp,
        operation=operation,
        object_type=object_type,
        object_id=object_id,
        attributes=attributes,
        raw_line=line,
    )
    _append_change(changes, change)


def _parse_bulk_operation(
    line: str,
    changes: SaiRedisChanges,
    allowed: Optional[Set[str]],
):
    """Parse a bulk sairedis operation (uses || as separator)"""
    # Format: timestamp|ACTION|objecttype||objectid|attr=value|...||objectid|attr=value|...
    fields = line.split("||")
    if len(fields) < 2:
        return

    header_parts = fields[0].split("|")
    if len(header_parts) < 3:
        return

    timestamp = header_parts[0]
    op_char = header_parts[1]
    operation = OPERATION_MAP.get(op_char)

    if not _should_keep(operation, allowed):
        return

    object_type = header_parts[2]

    for idx in range(1, len(fields)):
        obj_field = fields[idx]
        if not obj_field:
            continue

        obj_parts = obj_field.split("|")
        object_id = obj_parts[0] if obj_parts else ""
        attributes = _parse_attributes(obj_parts[1:])

        change = SaiObjectChange(
            timestamp=timestamp,
            operation=operation,
            object_type=object_type,
            object_id=object_id,
            attributes=attributes,
            raw_line=line,
        )
        _append_change(changes, change)
