import logging
import os
import re
import shlex
import uuid

import pytest

from tests.transceiver.attribute_parser.attribute_keys import EEPROM_ATTRIBUTES_KEY
from tests.transceiver.common import cli_helpers, dmesg_helpers
from tests.transceiver.common.eeprom_decode import is_stem_port
from tests.transceiver.eeprom.cmis._constants import (
    BG_READER_READ_INTERVAL_SEC,
    BG_READER_TMP_PREFIX,
)
from tests.transceiver.common.cli_parser_helper import RC_FAILURE
from tests.transceiver.common.cmis_helper import (
    CMIS_PAGE_01_CDB_CAP_PAGE,
    CMIS_PAGE_01_CDB_CAP_OFFSET,
    CMIS_PAGE_01_CDB_BG_MODE_BIT,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# LogAnalyzer suppression.  This test case deliberately exercises the I2C bus under
# concurrent EEPROM polling and CDB firmware-version reads; transient I2C
# error messages may appear in syslog/dmesg while the stress is running.
# The test scans dmesg itself and applies STRESS_TEST_I2C_ERROR_THRESHOLD,
# so let it own the failure decision — don't double-trip on loganalyzer at
# the framework level.  Patterns are intentionally narrow (i2c only) so
# unrelated kernel errors still surface.
# ──────────────────────────────────────────────────────────────────────

_EXPECTED_STRESS_LOG_PATTERNS = [
    r".*i2c[-_].*(error|fail|timeout|nack).*",
    r".*(error|fail|timeout|nack).*i2c[-_].*",
    r".*pmon#xcvrd.*Failed to read EEPROM.*",
]


@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_i2c_errors(duthost, loganalyzer):
    """Tell loganalyzer to ignore I2C error strings that the CDB stress test
    intentionally tolerates (up to STRESS_TEST_I2C_ERROR_THRESHOLD).

    The test owns the I2C-error pass/fail decision via its own dmesg scan;
    framework-level loganalyzer should not double-count.

    No-ops when loganalyzer is disabled (e.g. ``--disable_loganalyzer``).
    """
    if loganalyzer:
        loganalyzer[duthost.hostname].ignore_regex.extend(_EXPECTED_STRESS_LOG_PATTERNS)


# Maximum tolerated background EEPROM read failure rate during the CDB stress
# test.  A healthy module under CDB background mode should see essentially zero
# background-read failures; anything above a few percent indicates structural
# I2C bus disruption, not transient I/O noise.  The observed rate is always
# logged in the pass line so an operator can spot drift even when under
# threshold.
STRESS_EEPROM_MAX_FAIL_RATE = 0.05

# Number of I2C kernel-log errors tolerated before aborting a stress-test
# iteration loop.  A small number of transient errors can appear during normal
# background-mode operation; only a sustained burst warrants an early abort.
# The test result line always reports the observed count alongside this
# threshold so an operator can distinguish "0 errors" from "≤3 errors,
# under threshold".
STRESS_TEST_I2C_ERROR_THRESHOLD = 3

# dmesg ``grep -iE`` pattern for kernel I2C errors, passed to
# dmesg_helpers.scan_new_dmesg_errors().  Embedded in a single-quoted grep
# argument there, so it must not contain a single quote.
I2C_ERROR_PATTERN = r"i2c.*(error|fail|timeout|nack)|(error|fail).*i2c"

# Absolute path to the background-reader bash script shipped to the DUT by
# _RemoteBgReader.start().  Resolved from this module's location so it works
# regardless of the pytest invocation directory.
_BG_READER_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "scripts", "bg_eeprom_reader.sh"
)


class _RemoteBgReader(object):
    """Manage a background EEPROM polling loop running on the DUT.

    The bash loop is launched under ``setsid`` so it (and any in-flight
    ``sfputil`` child) form a dedicated process group; join() signals the
    whole group via ``kill -- -<pgid>`` instead of just SIGTERM-ing bash and
    leaving an orphan ``sfputil read-eeprom`` in flight on the I2C bus.

    Temp-file names include a short UUID fragment so concurrent test runs
    (e.g. parallel tox invocations) cannot collide on the same DUT files.
    All temp files share the ``BG_READER_TMP_PREFIX`` so the session-scoped
    cleanup fixture in conftest.py can ``rm -f`` everything left behind
    after a SIGKILL'd pytest run.
    """

    def __init__(self, host, sfp_port):
        safe_port = re.sub(r"[^A-Za-z0-9_.-]", "_", str(sfp_port))
        run_id = uuid.uuid4().hex[:8]
        self.host = host
        self.port = sfp_port
        # Process-group ID of the bash loop.  Equal to bash's own PID because
        # ``setsid`` makes bash the leader of a freshly-minted session/group.
        self.pgid = None
        # Final counters; populated by join() from the bash loop's EXIT trap.
        self.fail_count = 0
        self.total_count = 0
        # /tmp paths used by the bash loop and torn down at join() time.
        stem = f"{BG_READER_TMP_PREFIX}_{safe_port}_{run_id}"
        self.fail_file = f"{stem}_fail"
        self.total_file = f"{stem}_total"
        self.pgid_file = f"{stem}_pgid"
        # Per-run copy of the reader script on the DUT.  Shares the prefix so
        # the conftest cleanup fixture sweeps it after a SIGKILL'd run.
        self.script_file = f"{stem}_reader.sh"

    def start(self):
        """Ship the reader script to the DUT, launch it, and capture its PGID."""
        # 1. Copy the reader script to the DUT (auditable on disk rather than
        #    embedded as escaped inline bash).
        copy_result = self.host.copy(
            src=_BG_READER_SCRIPT, dest=self.script_file, mode="0644",
            module_ignore_errors=True,
        )
        if copy_result.get("failed"):
            logger.error(
                "Port %s: failed to copy bg reader script to DUT: %s",
                self.port, copy_result.get("msg"),
            )
            self.pgid = None
            return

        # 2. Launch under ``setsid`` so the script becomes a new session leader
        #    (PGID == its own PID), detached from the test runner's job-control
        #    group so 'kill -- -<pgid>' in join() is safe.  The script writes
        #    its own PID ($$) to pgid_file — the launcher's ``$!`` would point
        #    at the setsid wrapper, not the script, since setsid forks before
        #    exec.  The read-eeprom command is passed in so its spelling stays
        #    single-sourced from cli_helpers.
        # 3. Poll pgid_file for up to ~2 s and echo its contents; that value
        #    (the script's PID) is the PGID used for signal delivery in join().
        cmd = (
            f"setsid bash '{self.script_file}' "
            f"'{self.port}' '{self.fail_file}' '{self.total_file}' "
            f"'{self.pgid_file}' '{cli_helpers.SFPUTIL_READ_EEPROM}' "
            f"'{BG_READER_READ_INTERVAL_SEC}' "
            f"</dev/null >/dev/null 2>&1 & "
            f"for _ in $(seq 1 20); do "
            f"if [ -s \"{self.pgid_file}\" ]; then "
            f"cat \"{self.pgid_file}\"; exit 0; "
            f"fi; "
            f"sleep 0.1; "
            f"done; "
            f"echo \"\"; exit 1"
        )
        result = self.host.shell(cmd, module_ignore_errors=True)
        pgid_str = (result.get('stdout') or '').strip()
        if result.get('rc', RC_FAILURE) == 0 and pgid_str:
            try:
                self.pgid = int(pgid_str)
                if self.pgid <= 0:
                    raise ValueError(f"non-positive PGID: {pgid_str!r}")
                return                                   # PGID captured — success
            except (TypeError, ValueError) as exc:
                logger.error(
                    "Port %s: failed to parse background reader PGID: %s",
                    self.port, exc,
                )
        # Capture failed (non-zero rc, empty pgid file, or unparseable PID), but
        # the detached reader launched above may already be looping on the I2C
        # bus.  Without a PGID, join() can't signal it, and the conftest cleanup
        # only rm's the temp files — it never stops the process.  Kill it by its
        # unique per-run script path so it can't outlive start().
        self.pgid = None
        self._pkill_by_script_path()

    def _pkill_by_script_path(self):
        """Best-effort kill of this reader by its unique per-run script path.

        ``script_file`` is UUID-stamped, so ``pkill -f`` matches only THIS
        reader (safe under xdist / parallel-port runs).  Needed because the
        conftest cleanup ``rm -f``'s the temp files but never stops the process,
        and a reader whose PGID we failed to capture is otherwise unkillable for
        the rest of the session — it would keep polling the I2C bus.  ``pkill``
        excludes its own PID, so matching its own command line is not a concern.
        """
        quoted = shlex.quote(self.script_file)
        self.host.shell(
            f"pkill -TERM -f {quoted} 2>/dev/null; sleep 0.5; "
            f"pkill -KILL -f {quoted} 2>/dev/null || true",
            module_ignore_errors=True,
        )

    def join(self, timeout=10):
        """Stop the background process group and retrieve the final counters.

        Sends SIGTERM to the whole process group (``-<pgid>``), polls every
        100 ms for up to ``timeout`` seconds, then escalates to SIGKILL on
        the group as a fallback.  Both signals target ``-<pgid>`` so any
        in-flight ``sfputil`` child dies with bash — no orphans.

        Liveness is probed at the GROUP level (``pgrep -g <pgid>``), not the
        leader PID: a slow ``sfputil`` child can outlive the bash leader, so a
        leader-PID probe would prematurely declare the group gone and skip the
        SIGKILL escalation.

        Args:
            timeout: maximum seconds to wait for the remote process group to
                     exit after receiving SIGTERM (default 10 s).
        """
        # 0.1s poll interval below → 10 polls per second.
        wait_iterations = max(1, int(timeout) * 10)
        if self.pgid is not None:
            # kill -- -<PGID> targets the whole process group.
            self.host.shell(f"kill -- -{self.pgid}", module_ignore_errors=True)
            # SIGTERM wait loop — break as soon as the whole group is empty.
            # Probe the GROUP (pgrep -g), not the leader PID: the bash leader can
            # exit its EXIT trap while a slow sfputil child is still mid-I2C, and
            # a leader-PID probe (kill -0 <pid>) would then wrongly report "gone"
            # and skip the SIGKILL escalation below — orphaning that child (and
            # risking a kill on a reused PID once the leader's PID is freed).
            self.host.shell(
                f"for _ in $(seq 1 {wait_iterations}); do "
                f"pgrep -g {self.pgid} >/dev/null 2>&1 || break; "
                f"sleep 0.1; "
                f"done",
                module_ignore_errors=True,
            )
            # SIGKILL fallback — gate on whether the GROUP still has any member
            # (pgrep -g), so a lingering sfputil child that outlived the bash
            # leader still triggers the kill -9 on the group.  Emit a sentinel so
            # the warning below knows whether the escalation actually fired.
            kill_check = self.host.shell(
                f"if pgrep -g {self.pgid} >/dev/null 2>&1; then "
                f"  kill -9 -- -{self.pgid} 2>/dev/null; echo killed; "
                f"else "
                f"  echo exited; "
                f"fi",
                module_ignore_errors=True,
            )
            if "killed" in (kill_check.get("stdout") or ""):
                logger.warning(
                    "Port %s: background EEPROM reader PGID %d ignored "
                    "SIGTERM for %.1fs; escalated to SIGKILL",
                    self.port, self.pgid, timeout,
                )
        fail_result = self.host.shell(
            f"cat {self.fail_file} 2>/dev/null || echo 0",
            module_ignore_errors=True,
        )
        total_result = self.host.shell(
            f"cat {self.total_file} 2>/dev/null || echo 0",
            module_ignore_errors=True,
        )
        # Best-effort cleanup of this reader's /tmp files.  The session-scoped
        # cleanup fixture in conftest.py picks up anything we miss (e.g. when
        # pytest is SIGKILL'd before we reach join()).
        self.host.shell(
            f"rm -f {self.fail_file} {self.total_file} {self.pgid_file} {self.script_file}",
            module_ignore_errors=True,
        )
        try:
            self.fail_count = int((fail_result.get('stdout') or '0').strip())
        except (TypeError, ValueError):
            self.fail_count = 0
        try:
            self.total_count = int((total_result.get('stdout') or '0').strip())
        except (TypeError, ValueError):
            self.total_count = 0


def test_cdb_background_mode_support_test(
    duthost, port_attributes_dict, lport_to_first_subport_mapping
):
    """Verify CMIS CDB background mode hardware capability against inventory configuration.

    Prerequisites per port (both must be satisfied or the port is silently skipped):
    - EEPROM_ATTRIBUTES: cmis_active_optical = True  (non-DAC CMIS module)
    - EEPROM_ATTRIBUTES: cdb_background_mode_supported is defined (True or False)

    Stem-port detection (used to skip breakout sub-ports that share an EEPROM
    with their parent) comes from
    ``tests.common.platform.interface_utils.get_lport_to_first_subport_mapping``
    — a port is the stem iff it maps to itself, so no per-platform port-number
    modulus is needed.

    For qualifying stem ports, reads CMIS Page 01h at sfputil offset 0xA3
    (= CMIS global byte 163 decimal, absolute address 0xA3 in the 256-byte
    page view) using:
        sfputil read-eeprom -p <port> -n 0x01 -o 0xA3 -s 1

    Extracts bit 5 of the returned byte and validates against expected configuration:
        cdb_background_mode_supported = True  → bit 5 must be 1 (hardware supports it)
        cdb_background_mode_supported = False → bit 5 must be 0 (hardware does not)

    Aggregates all failures for reporting.

    CMIS reference:
        Page 01h (Capabilities Advertising), CMIS global byte 163 (decimal) = 0xA3, bit 5:
        CDB background mode support advertisement.
        sfputil: -n 0x01 -o 0xA3  (upper page, 0xA3 - 0x80 = 0x23 = 35 bytes from page start)
    """
    all_failures = []

    for port, port_attrs in port_attributes_dict.items():
        # Only test stem (parent) ports.  In a breakout deployment a single
        # physical transceiver is represented by one stem port and one or more
        # sub-ports that share the same EEPROM; running CDB reads against the
        # sub-ports is redundant and can cause false failures on some ASIC
        # drivers.
        if not is_stem_port(port, lport_to_first_subport_mapping):
            logger.debug("Port %s is a breakout sub-port, skipping CDB check", port)
            continue
        if not port_attrs:
            logger.debug("Port %s has no attributes, skipping", port)
            continue

        eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})

        # Prerequisite 1: port must be a non-DAC CMIS module
        if not eeprom_attrs.get("cmis_active_optical"):
            logger.debug("Port %s: cmis_active_optical is not True, skipping CDB check", port)
            continue

        # Prerequisite 2: expected CDB background mode support must be defined
        expected_cdb_bg_mode = eeprom_attrs.get("cdb_background_mode_supported")
        if expected_cdb_bg_mode is None:
            logger.debug("Port %s: cdb_background_mode_supported not defined, skipping", port)
            continue

        # Read CMIS Page 01h, CMIS global byte 163 (decimal) = 0xA3 (sfputil offset 0xA3)
        byte_map, err = cli_helpers.sfputil_read_eeprom(
            duthost, port,
            page=f"0x{CMIS_PAGE_01_CDB_CAP_PAGE:02X}",
            offset=CMIS_PAGE_01_CDB_CAP_OFFSET,
            size=1,
        )
        if err:
            all_failures.append(f"{port}: {err}")
            continue

        if not byte_map:
            all_failures.append(
                f"{port}: no parseable byte found in sfputil read-eeprom output "
                f"(page 0x{CMIS_PAGE_01_CDB_CAP_PAGE:02X}, "
                f"offset 0x{CMIS_PAGE_01_CDB_CAP_OFFSET:02X})"
            )
            continue

        # Extract bit 5 from the single returned byte
        raw_byte = byte_map.get(CMIS_PAGE_01_CDB_CAP_OFFSET)
        if raw_byte is None:
            all_failures.append(
                f"{port}: expected byte missing at offset 0x{CMIS_PAGE_01_CDB_CAP_OFFSET:02X} "
                f"in parsed sfputil output (keys: {sorted(byte_map.keys())})"
            )
            continue
        actual_bit = (raw_byte >> CMIS_PAGE_01_CDB_BG_MODE_BIT) & 0x01
        expected_bit = 1 if expected_cdb_bg_mode else 0

        if actual_bit != expected_bit:
            all_failures.append(
                f"{port}: CDB background mode mismatch: "
                f"expected bit {CMIS_PAGE_01_CDB_BG_MODE_BIT} = {expected_bit} "
                f"(cdb_background_mode_supported={expected_cdb_bg_mode}), "
                f"got bit {CMIS_PAGE_01_CDB_BG_MODE_BIT} = {actual_bit} "
                f"(raw byte: 0x{raw_byte:02X}, "
                f"page 0x{CMIS_PAGE_01_CDB_CAP_PAGE:02X} "
                f"offset 0x{CMIS_PAGE_01_CDB_CAP_OFFSET:02X})"
            )
        else:
            logger.debug(
                "Port %s CDB background mode verified: bit %d = %d "
                "(cdb_background_mode_supported=%s, raw byte: 0x%02X)",
                port, CMIS_PAGE_01_CDB_BG_MODE_BIT, actual_bit, expected_cdb_bg_mode, raw_byte,
            )

    if all_failures:
        pytest.fail("CDB background mode verification failures:\n" + "\n".join(all_failures))


# ──────────────────────────────────────────────────────────────────────
# Private helpers for the CDB background-mode stress test .
# The orchestrator (test_cdb_background_mode_stress_test) below is a
# thin loop that delegates each phase to one of these helpers.
# ──────────────────────────────────────────────────────────────────────


def _stress_port_in_scope(port, port_attrs, stem_map):
    """Return True iff ``port`` qualifies for the CDB stress test.

    Encapsulates the four skip gates (stem port, non-empty attrs,
    cmis_active_optical, cdb_background_mode_supported); logs the reason at
    DEBUG level for every port that is filtered out, so a single grep of
    the run log explains why any port was skipped.
    """
    if not is_stem_port(port, stem_map):
        logger.debug("Port %s is a breakout sub-port, skipping stress test", port)
        return False
    if not port_attrs:
        logger.debug("Port %s has no attributes, skipping", port)
        return False
    eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})
    if not eeprom_attrs.get("cmis_active_optical"):
        logger.debug("Port %s: cmis_active_optical is not True, skipping", port)
        return False
    if not eeprom_attrs.get("cdb_background_mode_supported"):
        logger.debug(
            "Port %s: cdb_background_mode_supported is not True, skipping", port
        )
        return False
    return True


def _run_cdb_fwversion_stress_loop(duthost, port, iterations, start_uptime):
    """Run the per-iteration ``sfputil show fwversion`` loop with I2C error
    monitoring.

    Returns ``(iteration_failures, cumulative_i2c_errors)``.  The loop
    aborts early once ``cumulative_i2c_errors`` exceeds
    ``STRESS_TEST_I2C_ERROR_THRESHOLD``; that abort itself appears as a
    failure entry in ``iteration_failures`` so the caller's aggregated
    report explains why the loop short-circuited.
    """
    iteration_failures = []
    cumulative_i2c_errors = []
    seen_i2c_errors = set()

    for iteration in range(1, iterations + 1):
        logger.debug("Port %s: CDB stress iteration %d/%d", port, iteration, iterations)

        _, err = cli_helpers.sfputil_show_fwversion(duthost, port)
        if err:
            iteration_failures.append(f"Iteration {iteration}/{iterations}: {err}")

        truly_new = dmesg_helpers.scan_new_dmesg_errors(
            duthost, start_uptime, seen_i2c_errors, I2C_ERROR_PATTERN
        )
        if not truly_new:
            continue

        cumulative_i2c_errors.extend(truly_new)
        logger.warning(
            "Port %s: %d new I2C error(s) after iteration %d "
            "(%d cumulative, threshold=%d)",
            port, len(truly_new), iteration,
            len(cumulative_i2c_errors), STRESS_TEST_I2C_ERROR_THRESHOLD,
        )
        if len(cumulative_i2c_errors) > STRESS_TEST_I2C_ERROR_THRESHOLD:
            iteration_failures.append(
                f"I2C kernel errors exceeded threshold "
                f"({len(cumulative_i2c_errors)} > {STRESS_TEST_I2C_ERROR_THRESHOLD}) "
                f"after iteration {iteration}/{iterations}:\n    "
                + "\n    ".join(cumulative_i2c_errors[:10])
            )
            logger.warning(
                "Port %s: I2C error threshold exceeded — aborting stress loop", port,
            )
            break

    return iteration_failures, cumulative_i2c_errors


def _evaluate_bg_reader_results(port, bg_reader):
    """Compute the background-EEPROM-reader stats and emit per-port logging.

    Returns ``(failures, total, failed, fail_rate)``.  ``failures`` is a
    list with a single string entry iff ``fail_rate`` exceeded
    ``STRESS_EEPROM_MAX_FAIL_RATE``; otherwise empty.  ``total`` /
    ``failed`` / ``fail_rate`` are returned so the orchestrator can
    include them in the per-port pass line.
    """
    total = bg_reader.total_count
    failed = bg_reader.fail_count
    fail_rate = (failed / total) if total > 0 else 0.0

    failures = []
    if total > 0:
        logger.info(
            "Port %s: background EEPROM reads — %d total, %d failed (%.2f%%)",
            port, total, failed, fail_rate * 100,
        )
        if fail_rate > STRESS_EEPROM_MAX_FAIL_RATE:
            failures.append(
                f"Background EEPROM read failure rate too high: "
                f"{failed}/{total} ({fail_rate * 100:.2f}%) reads failed "
                f"(threshold: {STRESS_EEPROM_MAX_FAIL_RATE * 100:.2f}%)"
            )
    else:
        logger.warning("Port %s: background EEPROM reader made no attempts", port)

    return failures, total, failed, fail_rate


def _run_cdb_stress_for_port(duthost, port, port_attrs):
    """Drive the full per-port stress sequence: epoch capture → start
    background reader → stress loop → stop background reader → evaluate
    results.

    Returns a list of per-port failure strings (empty on success).  The
    bg-reader join always runs (via ``finally``) so a mid-loop exception
    cannot leave a stray bash process group on the DUT.
    """
    eeprom_attrs = port_attrs.get(EEPROM_ATTRIBUTES_KEY, {})
    # Per-port iteration count comes from the EEPROM inventory attribute; its
    # default (10) lives in eeprom.json's ``defaults`` block, not in this test
    # (see the "CDB background mode stress test" case in eeprom_test_plan.md). A
    # port that reaches the stress test without it is an inventory
    # misconfiguration, so fail rather than silently substituting a count.
    iterations = eeprom_attrs.get("cdb_stress_iteration_count")
    if iterations is None:
        return [
            "EEPROM_ATTRIBUTES.cdb_stress_iteration_count is not defined in the "
            "inventory for this port; it is required for the CDB background-mode "
            "stress test (set it in eeprom.json defaults or per-PN)"
        ]
    logger.info(
        "Port %s: starting CDB background mode stress test (%d iterations)",
        port, iterations,
    )

    # Step 1 – dmesg uptime (seconds-since-boot) watermark
    start_uptime = dmesg_helpers.capture_dmesg_uptime_watermark(duthost)

    # Step 2 – background EEPROM reader (concurrent I2C load)
    bg_reader = _RemoteBgReader(duthost, port)
    bg_reader.start()
    if bg_reader.pgid is None:
        # If start() never captured a PGID, the stress loop would run with
        # zero background load — defeating the test's purpose.  Treat as a
        # per-port failure and move on.
        return [
            "failed to start background EEPROM reader "
            "(no PGID captured); stress traffic would be absent — skipping port"
        ]

    port_failures = []
    cumulative_i2c_errors = []
    try:
        # Steps 3 + 4 – CDB fwversion read loop with I2C error monitoring
        port_failures, cumulative_i2c_errors = _run_cdb_fwversion_stress_loop(
            duthost, port, iterations, start_uptime,
        )
    finally:
        # Step 5 – stop background process group unconditionally
        bg_reader.join(timeout=10)

    # Step 6 – evaluate background EEPROM reader stats
    bg_failures, total, failed, fail_rate = _evaluate_bg_reader_results(port, bg_reader)
    port_failures.extend(bg_failures)

    if not port_failures:
        # Surface the observed fail-rate in the pass line too so drift below
        # the threshold is still visible at a glance.
        logger.info(
            "Port %s: CDB background mode stress test passed (%d iterations, "
            "%d/%d background EEPROM reads succeeded, fail-rate %.2f%% ≤ %.2f%%, "
            "I2C kernel errors observed: %d (≤ threshold %d))",
            port, iterations, total - failed, total,
            fail_rate * 100, STRESS_EEPROM_MAX_FAIL_RATE * 100,
            len(cumulative_i2c_errors), STRESS_TEST_I2C_ERROR_THRESHOLD,
        )

    return port_failures


def test_cdb_background_mode_stress_test(
    duthost, port_attributes_dict, lport_to_first_subport_mapping
):
    """CDB background mode stress test for CMIS transceivers.

    Prerequisites per port (silently skipped when not met):
      - ``EEPROM_ATTRIBUTES.cmis_active_optical`` is True (non-DAC CMIS)
      - ``EEPROM_ATTRIBUTES.cdb_background_mode_supported`` is True
    Both gates plus the stem-port filter are evaluated by
    ``_stress_port_in_scope``.

    For each qualifying stem port the helper ``_run_cdb_stress_for_port``:
      1. Records a seconds-since-boot watermark (``/proc/uptime`` on the DUT).
      2. Starts a background EEPROM reader thread (concurrent I2C traffic).
      3. Reads CDB firmware version for
         ``EEPROM_ATTRIBUTES.cdb_stress_iteration_count`` iterations
         (required per-port inventory attribute, see the "CDB background mode
         stress test" case in eeprom_test_plan.md; the port fails if it is
         undefined — its default of 10 is supplied by eeprom.json defaults).
      4. After each iteration scans dmesg for new I2C errors; aborts early
         once the cumulative count exceeds
         ``STRESS_TEST_I2C_ERROR_THRESHOLD``.
      5. Stops the background reader (joined with a 10 s timeout, always).
      6. Reports a failure if the background EEPROM read fail rate exceeds
         ``STRESS_EEPROM_MAX_FAIL_RATE``.

    Expected result: every configured iteration completes AND the observed
    I2C kernel-error count stays at-or-below the threshold.  The per-port
    pass line reports the observed counters so drift below the threshold is
    visible at a glance.  Per-port failures are aggregated into one
    ``pytest.fail`` at the end so a single run surfaces every misbehaving
    port.
    """
    all_failures = []
    for port, port_attrs in port_attributes_dict.items():
        if not _stress_port_in_scope(port, port_attrs, lport_to_first_subport_mapping):
            continue
        port_failures = _run_cdb_stress_for_port(duthost, port, port_attrs)
        if port_failures:
            all_failures.append(f"{port}:\n  " + "\n  ".join(port_failures))

    if all_failures:
        pytest.fail(
            "CDB background mode stress test failures:\n" + "\n".join(all_failures)
        )
