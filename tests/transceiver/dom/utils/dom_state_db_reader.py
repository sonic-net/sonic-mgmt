"""STATE_DB readers and value parsers for DOM tests."""

import ast
import json
import logging
import re
from datetime import datetime, timezone


logger = logging.getLogger(__name__)

_FLOAT_PATTERN = re.compile(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?")


def parse_hgetall_output(stdout_lines):
    """Parse Redis HGETALL output from list or serialized-dict formats.

    Args:
        stdout_lines: Command output lines returned by ``sonic-db-cli`` or ``redis-cli``.

    Returns:
        dict: Parsed hash field/value pairs, or an empty dict when output is unusable.
    """
    lines = [line.strip() for line in stdout_lines if str(line).strip()]
    if not lines:
        return {}

    # Some platforms return HGETALL as a single serialized dict line.
    if len(lines) == 1:
        raw = lines[0]
        if raw in ("{}", "[]"):
            return {}

        for parser in (json.loads, ast.literal_eval):
            try:
                parsed = parser(raw)
            except Exception:
                continue
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}

    if len(lines) % 2 != 0:
        logger.warning("Unexpected HGETALL output line count=%d lines=%s", len(lines), lines)
        return {}

    parsed = {}
    for idx in range(0, len(lines), 2):
        parsed[lines[idx]] = lines[idx + 1]
    return parsed


def read_state_db_hash(duthost, key, namespace=None):
    """Read one STATE_DB hash with multi-ASIC namespace lookup support.

    Args:
        duthost: DUT host fixture used to execute database commands.
        key: STATE_DB hash key to read.
        namespace: Optional ASIC namespace to query before generic lookup.

    Returns:
        dict: Parsed hash field/value pairs, or an empty dict if the key cannot be read.
    """
    commands = []

    if namespace:
        commands.append('sonic-db-cli -n {} STATE_DB HGETALL "{}"'.format(namespace, key))
    elif getattr(duthost, "is_multi_asic", False):
        for asic in getattr(duthost, "frontend_asics", []):
            commands.append('sonic-db-cli -n {} STATE_DB HGETALL "{}"'.format(asic.namespace, key))

    commands.extend([
        'sonic-db-cli STATE_DB HGETALL "{}"'.format(key),
        'redis-cli --raw -n 6 HGETALL "{}"'.format(key),
    ])

    for cmd in commands:
        result = duthost.command(cmd, module_ignore_errors=True)
        if result.get("rc", 1) != 0:
            continue
        parsed = parse_hgetall_output(result.get("stdout_lines", []))
        if parsed:
            return parsed

    return {}


def parse_numeric(value):
    """Parse the first floating-point number from a DOM STATE_DB value.

    Args:
        value: Raw DOM value, potentially containing units or non-numeric text.

    Returns:
        float | None: Parsed number, or ``None`` when no valid number is present.
    """
    if value is None:
        return None

    text = str(value).strip()
    if not text or text.upper() in ("N/A", "NA", "NONE"):
        return None

    match = _FLOAT_PATTERN.search(text)
    if not match:
        return None

    try:
        return float(match.group(0))
    except ValueError:
        return None


def parse_update_time(value):
    """Parse a DOM last_update_time value into a timezone-aware UTC datetime.

    Args:
        value: Raw ``last_update_time`` value from DOM sensor data.

    Returns:
        datetime | None: Parsed UTC timestamp, or ``None`` when parsing fails.
    """
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    # Epoch seconds or milliseconds.
    numeric = parse_numeric(raw)
    if numeric is not None and raw.replace(".", "", 1).isdigit():
        epoch_sec = numeric / 1000.0 if numeric > 1e12 else numeric
        try:
            return datetime.fromtimestamp(epoch_sec, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            pass

    iso_text = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(iso_text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        pass

    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%a %b %d %H:%M:%S %Y",
    )
    for fmt in formats:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    # Normalize repeated spaces (e.g., day-of-month formatting differences) and try again.
    normalized = " ".join(raw.split())
    if normalized != raw:
        for fmt in formats:
            try:
                return datetime.strptime(normalized, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    return None
