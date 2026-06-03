"""
PFC Watchdog (PFCWD) Timer Accuracy Test - L3 Single-Node (spytest)
DETECTION-ONLY suite.

Validates the PFCWD *detect_time* and *poll_interval* boundary behavior.

Test strategy:
  * Continuous data stream P1 -> P3 at DATA_RATE_PERCENT line rate, lossless TC.
  * XOFF stream on P3 (toward DUT) at 105% of the platform/port-speed-specific
    "full block" rate, calculated from PFC pause quanta.
  * PFCWD is reconfigured per suite via:
        pfcwd start --action drop --restoration-time <R> all <D>
        config pfcwd interval <P>
    and restored to the module-setup defaults on teardown.
  * Two suites are run:
        Suite 1 (TestPfcwdTimer400ms): detect=400, restore=400, poll=100
        Suite 2 (TestPfcwdTimer200ms): detect=200, restore=200, poll=200
  * Each suite runs three single_burst XOFF transmissions:
        Phase A (negative): burst = detect_time      -> must NOT trigger
        Phase B (positive): burst = detect + poll    -> MUST trigger
        Phase C (positive, long):
                Suite 1: burst = 2 * detect          -> MUST trigger
                Suite 2: burst = 3 * detect          -> MUST trigger
                (3x in Suite 2 because detect==poll makes 2*detect == detect+poll)
  * Detection is asserted via the per-queue STORM_DETECTED counter from
    `pfcwd show stats`. This is more reliable than greppping syslog because
    some platforms (e.g. Cisco-8000) do not emit the orchagent
    "PFC Watchdog detected PFC storm" log line.

Restoration-timer behavior is covered by the sibling file
`test_v6_pfcwd_timer_restoration_l3_1node.py`.
"""

import pytest

from spytest import st

import pfcwd_timer_common  # noqa: F401  (ensures fixtures are importable)
# Expose the L3 PFCWD module as ``_mode_mod`` so the shared timer
# fixtures can resolve it via ``request.module._mode_mod`` without
# relying on a process-wide global. Must happen at import time, before
# pytest collects fixtures.
import test_v6_pfcwd_l3_1node as _mode_mod  # noqa: F401

from pfcwd_timer_common import (
    _apply_pfcwd_timing,
    _ctx,
    _exec_phase,
    # Module-scoped autouse fixture; importing the name is enough for
    # pytest's fixture discovery.
    pfcwd_timer_data_stream,  # noqa: F401
)
# pfcwd_timer_data_stream depends on pfcwd_module_setup; pytest looks up
# fixture dependencies in the TEST module's namespace, so it must be
# imported here.
from test_v6_pfcwd_l3_1node import pfcwd_module_setup  # noqa: F401


# ---------------------------------------------------------------------------
# Suite 1: detect=400ms, restore=400ms, poll=100ms
# ---------------------------------------------------------------------------

class TestPfcwdTimer400ms:
    """PFCWD timer accuracy with detect=400ms, restore=400ms, poll=100ms."""

    DETECT_MS = 400
    RESTORE_MS = 400
    POLL_MS = 100

    @pytest.fixture(scope='class', autouse=True)
    def configure_pfcwd(self):
        _apply_pfcwd_timing(
            _ctx['dut'], self.DETECT_MS, self.RESTORE_MS, self.POLL_MS,
        )
        _ctx['cfg_restore_ms'] = self.RESTORE_MS
        _ctx['poll_ms'] = self.POLL_MS
        yield

    def test_pfcwd_timer_no_detect_at_detect_time(self):
        """Negative: burst = detect_time (400ms). PFCWD must NOT trigger."""
        burst_sec = self.DETECT_MS / 1000.0
        ok = _exec_phase(burst_sec, expect_detect=False,
                         phase_label=f"A_no_detect_{self.DETECT_MS}")
        if not ok:
            st.report_fail(
                'msg',
                f"Burst={self.DETECT_MS}ms: expected no PFCWD detection, "
                f"but storm was detected"
            )
        st.report_pass("test_case_passed",
                       "test_pfcwd_timer_no_detect_at_detect_time passed")

    def test_pfcwd_timer_detect_at_detect_plus_poll(self):
        """Positive (boundary): burst = detect + poll. PFCWD must trigger
        in at least one of N iterations.

        At this exact boundary, alignment between the PFCWD poll cadence
        and the XOFF burst can cause occasional misses. We run ALL
        MAX_ITERS iterations to characterize detection probability, and
        pass if ANY iteration detects a storm.
        """
        MAX_ITERS = 7
        burst_ms = self.DETECT_MS + self.POLL_MS
        burst_sec = burst_ms / 1000.0
        detections = 0
        results = []
        for i in range(1, MAX_ITERS + 1):
            st.wait(2)
            ok = _exec_phase(burst_sec, expect_detect=True,
                             phase_label=f"B_detect_{burst_ms}_iter{i}")
            results.append('DETECT' if ok else 'miss')
            if ok:
                detections += 1
            st.log(f"Phase B iter {i}/{MAX_ITERS}: "
                   f"{'DETECTED' if ok else 'no detection'}")
        st.log(f"Phase B summary: detected {detections}/{MAX_ITERS} "
               f"iterations: {results}")
        if detections == 0:
            st.report_fail(
                'msg',
                f"Burst={burst_ms}ms: expected PFCWD detection in at least "
                f"1 of {MAX_ITERS} iterations, but storm was NEVER detected"
            )
        st.report_pass(
            "test_case_passed",
            f"test_pfcwd_timer_detect_at_detect_plus_poll passed "
            f"(detected {detections}/{MAX_ITERS} iterations)",
        )

    def test_pfcwd_timer_detect_at_2x_detect_time(self):
        """Positive: burst = 2 * detect_time. PFCWD MUST trigger."""
        st.wait(2)
        burst_ms = 2 * self.DETECT_MS
        burst_sec = burst_ms / 1000.0
        ok = _exec_phase(burst_sec, expect_detect=True,
                         phase_label=f"C_detect_long_{burst_ms}")
        if not ok:
            st.report_fail(
                'msg',
                f"Burst={burst_ms}ms: expected PFCWD detection, "
                f"but storm was NOT detected"
            )
        st.report_pass("test_case_passed",
                       "test_pfcwd_timer_detect_at_2x_detect_time passed")


# ---------------------------------------------------------------------------
# Suite 2: detect=200ms, restore=200ms, poll=200ms
# ---------------------------------------------------------------------------

class TestPfcwdTimer200ms:
    """
    PFCWD timer accuracy with detect=200ms, restore=200ms, poll=200ms.

    Note: because detect == poll, the "detect + poll" duration (400ms)
    equals "2 * detect" (also 400ms), so Phase C uses 3 * detect (600ms)
    to keep three meaningfully distinct cases.
    """

    DETECT_MS = 200
    RESTORE_MS = 200
    POLL_MS = 200

    @pytest.fixture(scope='class', autouse=True)
    def configure_pfcwd(self):
        _apply_pfcwd_timing(
            _ctx['dut'], self.DETECT_MS, self.RESTORE_MS, self.POLL_MS,
        )
        _ctx['cfg_restore_ms'] = self.RESTORE_MS
        _ctx['poll_ms'] = self.POLL_MS
        yield

    def test_pfcwd_timer_no_detect_at_detect_time_200ms(self):
        """Negative: burst = detect_time (200ms). PFCWD must NOT trigger."""
        burst_sec = self.DETECT_MS / 1000.0
        ok = _exec_phase(burst_sec, expect_detect=False,
                         phase_label=f"A_no_detect_{self.DETECT_MS}")
        if not ok:
            st.report_fail(
                'msg',
                f"Burst={self.DETECT_MS}ms: expected no PFCWD detection, "
                f"but storm was detected"
            )
        st.report_pass(
            "test_case_passed",
            "test_pfcwd_timer_no_detect_at_detect_time_200ms passed",
        )

    def test_pfcwd_timer_detect_at_detect_plus_poll_200ms(self):
        """Positive (boundary): burst = detect + poll (400ms). PFCWD must
        trigger in at least one of N iterations.

        At this exact boundary, alignment between the PFCWD poll cadence
        and the XOFF burst can cause occasional misses. We run ALL
        MAX_ITERS iterations to characterize detection probability, and
        pass if ANY iteration detects a storm.
        """
        MAX_ITERS = 7
        burst_ms = self.DETECT_MS + self.POLL_MS
        burst_sec = burst_ms / 1000.0
        detections = 0
        results = []
        for i in range(1, MAX_ITERS + 1):
            st.wait(2)
            ok = _exec_phase(burst_sec, expect_detect=True,
                             phase_label=f"B_detect_{burst_ms}_iter{i}")
            results.append('DETECT' if ok else 'miss')
            if ok:
                detections += 1
            st.log(f"Phase B iter {i}/{MAX_ITERS}: "
                   f"{'DETECTED' if ok else 'no detection'}")
        st.log(f"Phase B summary: detected {detections}/{MAX_ITERS} "
               f"iterations: {results}")
        if detections == 0:
            st.report_fail(
                'msg',
                f"Burst={burst_ms}ms: expected PFCWD detection in at least "
                f"1 of {MAX_ITERS} iterations, but storm was NEVER detected"
            )
        st.report_pass(
            "test_case_passed",
            f"test_pfcwd_timer_detect_at_detect_plus_poll_200ms passed "
            f"(detected {detections}/{MAX_ITERS} iterations)",
        )

    def test_pfcwd_timer_detect_at_3x_detect_time_200ms(self):
        """
        Positive (long): burst = 3 * detect_time (600ms).

        Using 3x (not 2x) because with detect==poll, 2*detect == detect+poll
        and would duplicate the previous case.
        """
        st.wait(2)
        burst_ms = 3 * self.DETECT_MS
        burst_sec = burst_ms / 1000.0
        ok = _exec_phase(burst_sec, expect_detect=True,
                         phase_label=f"C_detect_long_{burst_ms}")
        if not ok:
            st.report_fail(
                'msg',
                f"Burst={burst_ms}ms: expected PFCWD detection, "
                f"but storm was NOT detected"
            )
        st.report_pass(
            "test_case_passed",
            "test_pfcwd_timer_detect_at_3x_detect_time_200ms passed",
        )
