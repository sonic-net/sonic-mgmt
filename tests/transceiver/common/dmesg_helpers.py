r"""Shared dmesg (kernel ring-buffer) scanning helpers for transceiver tests.

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

Why a dedicated scanner instead of the autouse loganalyzer framework?
  This is a natural "isn't this redundant?" question — it is not, for four
  reasons.  loganalyzer structurally cannot serve as the I2C-error gate here:

  1. loganalyzer actively *ignores* I2C errors.  Its common-ignore set filters
     exactly this class of message (e.g. ``loganalyzer_common_ignore.txt``
     ``".* ERR kernel:.*ltc2497.*i2c transfer failed: -EFAULT"`` and the SCD
     I2C ack-error warnings), so even an ERR-severity I2C fault that reaches
     syslog is dropped as known noise.  This scanner is not subject to those
     ignores.
  2. Severity gap.  ``loganalyzer_common_match.txt`` is crash/ERR-centric
     (``\.ERR``, ``kernel:.*panic`` …) with no i2c/nack/timeout pattern and no
     warning-level catch-all, so bus faults emitted at warn/notice via
     ``dev_warn`` slip through.  This scanner covers emerg..warn with an
     I2C-specific regex.
  3. Source gap.  loganalyzer reads ``/var/log/syslog``; this reads the kernel
     ring buffer directly, so rate-limited / below-forwarding-threshold lines
     that never reach rsyslog (dmesg-only) are still caught.
  4. Granularity/ownership.  loganalyzer is whole-test, post-hoc, binary, and
     ``--disable_loganalyzer``-able; this runs per iteration for per-port
     attribution + early abort, making "no I2C errors during the loop" an
     assertion the test itself owns.

  There is partial overlap only for ERR-severity I2C lines that reach syslog
  and aren't in the ignore list — not enough to drop this helper.
"""
import re


# Default dmesg lines start with a kernel-monotonic timestamp in brackets:
#     [   123.456789] i2c i2c-1: error -110
# group(1) is seconds-since-boot, compared against the /proc/uptime watermark.
_DMESG_MONOTONIC_TS_RE = re.compile(r'^\[\s*(\d+(?:\.\d+)?)\]')

# Severity levels worth scanning. Genuine I2C hardware faults (bus errors,
# timeouts, NACKs) are emitted via dev_err/dev_warn and friends, never at
# info/notice/debug -- which is the bulk of ring-buffer volume. Bounding dmesg
# to these levels shrinks the input grep has to scan on each stress iteration
# (the scan is O(iterations x buffer) otherwise) without weakening the
# timestamp-window + seen_errors correctness guarantees below.
_DMESG_ERROR_LEVELS = "emerg,alert,crit,err,warn"


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

    ``dmesg --level`` bounds the scan to error/warning-class lines
    (:data:`_DMESG_ERROR_LEVELS`) so each iteration only greps the relevant
    slice of the ring buffer rather than the full info/debug-dominated buffer.
    """
    result = duthost.shell(
        "sudo dmesg --level=" + _DMESG_ERROR_LEVELS
        + " | grep -iE '" + grep_pattern + "' || true",
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
