"""
Utility functions for parsing sairedis.rec log files on DPU hosts.

This module provides tools to analyze SAI object changes (create, remove, set)
from /var/log/swss/sairedis.rec
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List

logger = logging.getLogger(__name__)


@dataclass
class SaiObjectChange:
    """Represents a single SAI object change from sairedis.rec"""
    timestamp: str
    operation: str  # 'create', 'remove', 'set'
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

    def summary(self) -> Dict[str, int]:
        """Return a summary count of changes by object type"""
        summary = {
            'created': defaultdict(int),
            'removed': defaultdict(int),
            'edited': defaultdict(int)
        }
        for change in self.created:
            summary['created'][change.object_type] += 1
        for change in self.removed:
            summary['removed'][change.object_type] += 1
        for change in self.edited:
            summary['edited'][change.object_type] += 1
        return {k: dict(v) for k, v in summary.items()}


def get_sairedis_line_count(dpuhost) -> int:
    result = dpuhost.shell("wc -l /var/log/swss/sairedis.rec | awk '{print $1}'", module_ignore_errors=True)
    if result['rc'] == 0:
        return int(result['stdout'].strip())
    return 0


def parse_sairedis_changes(dpuhost, start_line: int = 0) -> SaiRedisChanges:
    """
    Parse the sairedis.rec file on the DPU host and return all created, removed,
    and edited objects since the specified start line.

    Args:
        dpuhost: The DPU host object to run commands on
        start_line: The line number to start parsing from (0-based). Use get_sairedis_line_count()
                   at the start of the test to get this value.

    Returns:
        SaiRedisChanges object containing lists of created, removed, and edited objects
    """
    changes = SaiRedisChanges()

    # Operation map: single char to operation name
    # Lowercase = single operation, Uppercase = bulk operation
    operation_map = {
        'c': 'create', 'C': 'create',  # create / bulk create
        'r': 'remove', 'R': 'remove',  # remove / bulk remove
        's': 'set', 'S': 'set',        # set / bulk set
        'g': 'get', 'G': 'get',        # get / bulk get
        'n': 'notify',                  # notification
        'a': 'stats',                   # get stats
        'q': 'clearstats',              # clear stats
    }

    # Read the sairedis.rec file starting from the specified line
    if start_line > 0:
        cmd = f"tail -n +{start_line + 1} /var/log/swss/sairedis.rec"
    else:
        cmd = "cat /var/log/swss/sairedis.rec"

    result = dpuhost.shell(cmd, module_ignore_errors=True)
    if result['rc'] != 0:
        logger.warning(f"Failed to read sairedis.rec: {result.get('stderr', 'Unknown error')}")
        return changes

    lines = result['stdout'].splitlines()

    for line in lines:
        line = line.strip()
        if not line or 'SAI_OBJECT_TYPE' not in line:
            continue

        try:
            # Check if it's a bulk operation (uses || as separator)
            if '||' in line:
                _parse_bulk_operation(line, operation_map, changes)
            else:
                _parse_single_operation(line, operation_map, changes)
        except Exception as e:
            logger.debug(f"Failed to parse sairedis line: {line}, error: {e}")
            continue

    logger.info(f"Total SAI changes: {changes.summary()}")
    logger.info(f"Created objects: {len(changes.created)}")
    logger.info(f"Removed objects: {len(changes.removed)}")
    logger.info(f"Edited objects: {len(changes.edited)}")

    # Log details of each change for debugging
    for change in changes.created:
        logger.debug(f"Created: {change.object_type}:{change.object_id}")
    for change in changes.removed:
        logger.debug(f"Removed: {change.object_type}:{change.object_id}")
    for change in changes.edited:
        logger.debug(f"Edited: {change.object_type}:{change.object_id}")

    return changes


def _parse_single_operation(line: str, operation_map: Dict[str, str], changes: SaiRedisChanges):
    """Parse a single (non-bulk) sairedis operation"""
    parts = line.split('|')
    if len(parts) < 3:
        return

    timestamp = parts[0]
    op_char = parts[1]
    operation = operation_map.get(op_char)

    if not operation or operation in ('get', 'notify', 'stats', 'clearstats'):
        return

    # Parse object type and ID
    obj_part = parts[2]
    if ':' in obj_part:
        object_type, object_id = obj_part.split(':', 1)
    else:
        object_type = obj_part
        object_id = ""

    # Parse attributes (attr=value pairs)
    attributes = {}
    for part in parts[3:]:
        if '=' in part:
            key, value = part.split('=', 1)
            attributes[key] = value

    change = SaiObjectChange(
        timestamp=timestamp,
        operation=operation,
        object_type=object_type,
        object_id=object_id,
        attributes=attributes,
        raw_line=line
    )

    if operation == 'create':
        changes.created.append(change)
    elif operation == 'remove':
        changes.removed.append(change)
    elif operation == 'set':
        changes.edited.append(change)


def _parse_bulk_operation(line: str, operation_map: Dict[str, str], changes: SaiRedisChanges):
    """Parse a bulk sairedis operation (uses || as separator)"""
    # Format: timestamp|ACTION|objecttype||objectid|attr=value|...||objectid|attr=value|...
    fields = line.split('||')
    if len(fields) < 2:
        return

    # Parse header: timestamp|action|objecttype
    header_parts = fields[0].split('|')
    if len(header_parts) < 3:
        return

    timestamp = header_parts[0]
    op_char = header_parts[1]
    operation = operation_map.get(op_char)

    if not operation or operation in ('get', 'notify', 'stats', 'clearstats'):
        return

    object_type = header_parts[2]

    # Parse each object in the bulk operation
    for idx in range(1, len(fields)):
        obj_field = fields[idx]
        if not obj_field:
            continue

        obj_parts = obj_field.split('|')
        object_id = obj_parts[0] if obj_parts else ""

        # Parse attributes
        attributes = {}
        for part in obj_parts[1:]:
            if '=' in part:
                key, value = part.split('=', 1)
                attributes[key] = value

        change = SaiObjectChange(
            timestamp=timestamp,
            operation=operation,
            object_type=object_type,
            object_id=object_id,
            attributes=attributes,
            raw_line=line
        )

        if operation == 'create':
            changes.created.append(change)
        elif operation == 'remove':
            changes.removed.append(change)
        elif operation == 'set':
            changes.edited.append(change)
