"""Syslog watermark + scan helpers.

Mirrors ``dmesg_helpers.py``'s watermark/scan shape, but over
``/var/log/syslog`` line counts rather than dmesg's monotonic timestamps.
Used to assert the ABSENCE of a specific message pattern over an operation
window — e.g. confirming a transceiver reset generates no xcvrd OIR
(``Got SFP removed/inserted event``) log line.
"""
import logging

logger = logging.getLogger(__name__)

_SYSLOG_PATH = "/var/log/syslog"


def capture_syslog_line_watermark(duthost):
    """Return ``(line_count, err)`` for ``/var/log/syslog`` right now."""
    result = duthost.shell(f"wc -l < {_SYSLOG_PATH}", module_ignore_errors=True)
    if result.get("rc", 1) != 0:
        return None, (
            f"failed to capture syslog watermark: {(result.get('stderr') or '').strip()}"
        )
    try:
        return int((result.get("stdout") or "0").strip()), None
    except ValueError:
        return None, "could not parse syslog line-count watermark"


def scan_new_syslog_lines(duthost, watermark, grep_pattern):
    """Return ``(matching_lines, err)`` for lines appended to syslog since ``watermark``.

    Args:
        watermark: the line count from :func:`capture_syslog_line_watermark`,
            taken before the operation under test.
        grep_pattern: an extended-regex (``grep -E``) pattern.

    ``matching_lines`` is empty (with ``err`` ``None``) when nothing new
    matches — the expected outcome for an absence check.
    """
    if watermark is None:
        return [], "no syslog watermark captured - cannot scan for new lines"
    cmd = f"tail -n +{watermark + 1} {_SYSLOG_PATH} | grep -E '{grep_pattern}'"
    result = duthost.shell(cmd, module_ignore_errors=True)
    # grep exits 1 for "no matches" - that is a pass here, not a failure.
    if result.get("rc", 1) not in (0, 1):
        return [], f"failed to scan syslog for new lines: {(result.get('stderr') or '').strip()}"
    return [line for line in result.get("stdout_lines", []) if line.strip()], None
