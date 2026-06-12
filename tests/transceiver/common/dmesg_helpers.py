"""Shared dmesg (kernel ring-buffer) scanning helpers for transceiver tests.

Several tests need to watch the kernel log for errors emitted *during* an
operation — e.g. the CDB background-mode stress test watches for I2C errors
while it hammers the bus, and the CDB firmware-upgrade tests will watch for the
same class of errors during firmware writes.  The watermark + cumulative-dedup
scan implemented here is the reusable primitive for that; callers supply their
own ``grep -iE`` pattern so the module stays error-class agnostic.

The scan is anchored on a *seconds-since-boot* watermark (from ``/proc/uptime``)
rather than a dmesg line number, which keeps it robust against ring-buffer wraps
and concurrent ``dmesg -c`` invocations (both of which would invalidate a
line-number cursor).  We use the kernel's own monotonic timestamp (the default
``dmesg`` ``[<seconds-since-boot>]`` format) as the per-line clock so the window
can be filtered in plain Python — no ``awk``/``date`` timestamp gymnastics — and
so the comparison is immune to a test-runner-vs-DUT timezone mismatch or an NTP
step that wall-clock (``dmesg -T``) timestamps would be subject to.
"""
import re


# Default dmesg lines start with a kernel-monotonic timestamp in brackets:
#     [   123.456789] i2c i2c-1: error -110
# group(1) is seconds-since-boot, compared against the /proc/uptime watermark.
_DMESG_MONOTONIC_TS_RE = re.compile(r'^\[\s*(\d+(?:\.\d+)?)\]')


def capture_dmesg_uptime_watermark(duthost):
    """Read seconds-since-boot from ``/proc/uptime`` and return it as a float.

    This is the lower bound a subsequent :func:`scan_new_dmesg_errors` call
    filters on.  Returns 0.0 on any parse failure — 0.0 means "include
    everything in dmesg", which is safer than silently truncating the scan
    window.  ``/proc/uptime`` is the same monotonic clock dmesg stamps its lines
    with, so the watermark and the per-line timestamps are directly comparable
    regardless of the DUT's wall-clock timezone.
    """
    res = duthost.shell("cat /proc/uptime", module_ignore_errors=True)
    try:
        return float(res.get('stdout_lines', ['0'])[0].split()[0])
    except (ValueError, IndexError):
        return 0.0


def scan_new_dmesg_errors(duthost, start_uptime, seen_errors, grep_pattern):
    """Scan dmesg for lines matching ``grep_pattern`` stamped at-or-after
    ``start_uptime`` (seconds since boot), return only the lines not already in
    ``seen_errors``, and mutate ``seen_errors`` to include them.

    Only ``dmesg`` + ``grep`` run on the DUT; the timestamp-window filtering is
    done here in Python (matching the leading ``[<seconds-since-boot>]``) rather
    than in an ``awk`` + ``date`` pipeline — both more readable and timezone-safe.

    ``grep_pattern`` is a ``grep -iE`` (extended, case-insensitive) regex
    embedded into a single-quoted shell argument, so it must not itself contain
    a single quote.  Callers pass the error class they care about, e.g.
    ``i2c.*(error|fail|timeout|nack)|(error|fail).*i2c``.  ``|| true`` keeps the
    command at rc 0 so grep's exit-1-on-no-match is not mistaken for a failure
    under ``module_ignore_errors=True``.

    The de-dup matters: each scan is cumulative since the watermark, not
    iteration-delta.  Without the ``seen_errors`` filter the same error would be
    counted on every scan and a threshold would trip almost immediately on a
    single transient error.  The set also makes the count robust against a dmesg
    ring-buffer wrap mid-test: even if old errors fall out of dmesg, the set
    retains them so the cumulative count never shrinks.

    A matching line whose leading ``[<seconds>]`` timestamp can't be parsed is
    conservatively kept (not dropped), so an unrecognized format never silently
    hides an error.
    """
    result = duthost.shell(
        "sudo dmesg | grep -iE '" + grep_pattern + "' || true",
        module_ignore_errors=True,
    )
    truly_new = []
    for line in result.get('stdout_lines', []):
        line = line.strip()
        if not line:
            continue
        m = _DMESG_MONOTONIC_TS_RE.match(line)
        if m is not None and float(m.group(1)) < start_uptime:
            continue   # emitted before the watermark
        if line not in seen_errors:
            seen_errors.add(line)
            truly_new.append(line)
    return truly_new
