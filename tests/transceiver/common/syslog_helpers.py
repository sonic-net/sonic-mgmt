"""Syslog watermark + scan helpers.

Mirrors ``dmesg_helpers.py``'s watermark/scan shape, but over
``/var/log/syslog`` line counts rather than dmesg's monotonic timestamps.
Used to assert the ABSENCE of a specific message pattern over an operation
window — e.g. confirming a transceiver reset generates no xcvrd OIR
(``Got SFP removed/inserted event``) log line.
"""
import logging
import shlex

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
    """Return lines appended to syslog since ``watermark`` that match ``grep_pattern``.

    Args:
        duthost: DUT host object.
        watermark: line count from :func:`capture_syslog_line_watermark`.
        grep_pattern: bare ``grep -E`` regex; it is shell-quoted here.

    Returns:
        tuple: ``(matching_lines, err)``; ``matching_lines`` is empty when nothing new matches.
    """
    if watermark is None:
        return [], "no syslog watermark captured - cannot scan for new lines"
    cmd = f"tail -n +{watermark + 1} {_SYSLOG_PATH} | grep -E -- {shlex.quote(grep_pattern)}"
    result = duthost.shell(cmd, module_ignore_errors=True)
    # grep exits 1 when nothing matches.
    if result.get("rc", 1) not in (0, 1):
        return [], f"failed to scan syslog for new lines: {(result.get('stderr') or '').strip()}"
    return [line for line in result.get("stdout_lines", []) if line.strip()], None
