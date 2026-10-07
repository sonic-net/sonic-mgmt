"""Scan operation-scoped dmesg errors using monotonic timestamps."""
import re

_DMESG_MONOTONIC_TS_RE = re.compile(r'^\[\s*(\d+(?:\.\d+)?)\]')
_DMESG_ERROR_LEVELS = "emerg,alert,crit,err,warn"


def capture_dmesg_uptime_watermark(duthost):
    """Return ``(seconds_since_boot, err)`` for an operation-window watermark."""
    result = duthost.shell("cat /proc/uptime", module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        return None, "failed to capture dmesg uptime watermark"
    try:
        return float(result.get("stdout_lines", [])[0].split()[0]), None
    except (ValueError, IndexError):
        return None, "could not parse /proc/uptime for dmesg watermark"


def scan_new_dmesg_errors(duthost, start_uptime, seen_errors, grep_pattern):
    """Return ``(new_matching_lines, err)`` and update ``seen_errors``."""
    result = duthost.shell(
        "sudo dmesg --level=" + _DMESG_ERROR_LEVELS,
        module_ignore_errors=True,
    )
    if result.get("rc", 1) != 0:
        return [], "failed to read dmesg for operation-window errors"

    pattern = re.compile(grep_pattern, re.IGNORECASE)
    truly_new = []
    for line in result.get("stdout_lines", []):
        line = line.strip()
        if not line or pattern.search(line) is None:
            continue
        m = _DMESG_MONOTONIC_TS_RE.match(line)
        if m is not None and float(m.group(1)) < start_uptime:
            continue
        if line not in seen_errors:
            seen_errors.add(line)
            truly_new.append(line)
    return truly_new, None
