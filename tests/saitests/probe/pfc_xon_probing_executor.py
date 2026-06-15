"""
PFC XOn Probing Executor — 2-dst topology with fill+drain protocol

Detects pkts_num_dismiss_pfc + pkts_num_hysteresis (XOn offset) using
"drain after xoff" protocol:
  - fill phase: send packets via 2 flows (src->dst_drain, src->dst_holder)
    so they accumulate at the SAME ingress PG (same source port + same DSCP).
    Total = pfcxoff_point. Verify PFC_PAUSE_RX incremented (xoff fired).
  - drain phase: tx_enable(dst_drain) drains its portion. Wait. If buffer
    level fell past xon threshold, src is resumed -> sends more -> next
    xoff fires -> PFC_PAUSE_RX increments AGAIN.
  - decision: PAUSE counter incremented past baseline+1 = xon resumed.

Protocol conformance (C3 refactor 2026-06):
  This executor now conforms to ProbingExecutorProtocol (2-port interface):
    prepare(src_port, dst_port)
    check(src_port, dst_port, value, attempts=1, drain_buffer=True, iteration=0, **traffic_keys)
  The holder_port is internalized via __init__ — standard algorithms
  (ThresholdRangeProbingAlgorithm, ThresholdPointProbingAlgorithm) can
  drive this executor without knowing about the 2-dst topology.

  check(value=D) means: with D packets routed to dst_port (drain target)
  and (pfcxoff_point - D) routed to holder_port (stays tx_disabled), after
  opening dst_port's tx, did xon fire?

  drain_buffer parameter is accepted for protocol conformance but has no
  effect — every check is always a full fill-then-drain cycle.

Reference: legacy PFCXonTest (sai_qos_tests.py L2868) which uses 3-port
fan-out and compares pkts_num_dismiss_pfc + hysteresis offset.

Usage:
    executor = PfcXonProbingExecutor(
        ptftest=self,
        observer=observer,
        pfcxoff_point=N,        # known from prior PfcXoff probe
        holder_port=29,         # internalized holder port
        verbose=True,
    )
    executor.prepare(src, drain_port)
    success, xon_fired = executor.check(src, drain_port, value=D, **traffic_keys)
"""

import sys
import os
import time
from typing import Tuple

from executor_registry import ExecutorRegistry

try:
    from switch import (
        sai_thrift_read_port_counters,
        port_list,
    )
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.join(parent_dir, "py3"))
    try:
        from sai_qos_tests import PORT_TX_CTRL_DELAY, PFC_TRIGGER_DELAY
    except ImportError:
        PORT_TX_CTRL_DELAY = 2
        PFC_TRIGGER_DELAY = 2
except ImportError:
    PORT_TX_CTRL_DELAY = 2
    PFC_TRIGGER_DELAY = 2

    def sai_thrift_read_port_counters(client, asic_type, port):
        return [0] * 20, [0] * 10

    port_list = {"src": {}}


# Default tunables — can be overridden via __init__ kwargs
_DEFAULT_FILL_VERIFICATION_ATTEMPTS = 3   # how many times to retry fill if xoff doesn't fire
_DEFAULT_FILL_RETRY_MARGIN = 2            # extra packets to add when retrying fill
# NOTE (drain-bug fix 2026-05-08): default raised from 0.5s -> 2s (matches
# PFC_TRIGGER_DELAY) to be symmetric with the fill phase post-traffic wait.
# The 0.5s value was provisional and unvalidated on real hardware (UT/IT both
# patch time.sleep so the asymmetry was never exercised). After physical
# validation across Broadcom/Cisco/Mellanox confirms 0.5s is sufficient, this
# can be lowered per ASIC family via the constructor kwarg.
_DEFAULT_DRAIN_SETTLE_DELAY = 2           # seconds after tx_enable before reading counter

# NOTE (drain-bug fix 2026-05-08): physical TH2 validation revealed a
# fundamental flaw in the original `post_pause > baseline` decision.
# DUT emits PFC PAUSE frames PERIODICALLY (every ~450µs per IEEE 802.1Qbb
# in standard 802.3x mode) while xoff is asserted, so the pause counter
# increments continuously regardless of whether xon fired. Fix: compare a
# SECOND sample after a short observation window — if the counter froze
# (delta < tolerance), PFC has released and xon fired.
#
# Rate calibration: physical TH2 7260CX3 trace shows ~220 pauses per 100ms
# observation window (~2200 pauses/sec) while xoff active. Default tolerance
# of 5 gives ~44x margin over that observed rate. Mellanox/Cisco may differ;
# tune via constructor kwargs if the per-iteration `Drain check` trace
# shows growth values close to the tolerance during clearly-xoff iterations.
# seconds — short enough to bound iteration time, long enough to catch periodic PAUSE
_DEFAULT_PAUSE_OBSERVATION_WINDOW = 0.1
# max PAUSE delta in window to consider "stopped" (xon fired)
_DEFAULT_PAUSE_STOP_TOLERANCE = 5


@ExecutorRegistry.register(probe_type="pfc_xon", executor_env="physical")
class PfcXonProbingExecutor:
    """
    PFC XOn (XOn offset) Probing Executor.

    Topology: 1 src -> 2 dst (dst_port is the drain target, holder_port
    holds back its share of the buffer fill).
    Both dst flows enter the SAME ingress PG (same source port + same DSCP).

    Protocol conformance (C3 refactor 2026-06):
      Conforms to ProbingExecutorProtocol (2-port interface). holder_port is
      internalized in __init__ so standard algorithms can drive this executor
      without 3-port awareness.

    The constructor takes pfcxoff_point obtained from a prior PfcXoff probe
    so the executor knows the buffer fill level needed to trigger xoff.

    The check(value=D) logic:
      1. tx_disable both dst_port, holder_port
      2. drain residual buffer
      3. send D packets via flow(src->dst_port); send (pfcxoff_point - D) via
         flow(src->holder_port). Total = pfcxoff_point. xoff fires.
      4. (verify) read PFC_PAUSE_RX baseline. If not incremented from
         pre-fill snapshot, retry up to MAX_FILL_ATTEMPTS with margin.
      5. tx_enable(dst_port) -> drain D packets out
      6. wait DRAIN_SETTLE_DELAY (let buffer settle and PFC react)
      7. sample PFC_PAUSE_RX twice over PAUSE_OBSERVATION_WINDOW.
         - If counter delta < PAUSE_STOP_TOLERANCE => PFC has released
           (xon fired). Return (True, True).
         - Else (counter still incrementing because PFC is still asserted)
           => xon NOT fired at this D. Return (True, False).
      8. cleanup: tx_enable(holder_port) so next iteration has clean state.

    NOTE (drain-bug fix 2026-05-08, on real TH2 7260CX3): the original
    rule "PAUSE counter > baseline => xon fired" was based on a wrong
    assumption that PAUSE only increments on new xoff triggers. In fact
    the DUT emits PAUSE frames periodically while xoff is asserted, so
    the counter ALWAYS grows during xoff regardless of whether xon
    intermittently fired. The new rule observes whether the PAUSE stream
    has STOPPED — that is the true signal of xon release.
    """

    def __init__(
        self,
        ptftest,
        observer=None,
        pfcxoff_point: int = None,
        holder_port: int = None,
        verbose: bool = False,
        name: str = "",
        max_fill_attempts: int = _DEFAULT_FILL_VERIFICATION_ATTEMPTS,
        fill_retry_margin: int = _DEFAULT_FILL_RETRY_MARGIN,
        drain_settle_delay: float = _DEFAULT_DRAIN_SETTLE_DELAY,
        pause_observation_window: float = _DEFAULT_PAUSE_OBSERVATION_WINDOW,
        pause_stop_tolerance: int = _DEFAULT_PAUSE_STOP_TOLERANCE,
    ):
        """
        Args:
            ptftest: PTF test instance (provides buffer_ctrl, src_client,
                asic_type, cnt_pg_idx).
            observer: ProbingObserver for trace/metrics.
            pfcxoff_point: Known PfcXoff threshold in packets (from prior
                PfcXoff point probe). Required.
            holder_port: The dst port that holds buffer (not drained). Required
                for prepare/check calls; internalized so standard 2-port
                algorithms can drive this executor.
            verbose: Enable trace output.
            name: Identifier for this executor instance (e.g., "step3_drain").
            max_fill_attempts: How many times to retry fill if xoff doesn't
                fire (noise tolerance, like ThresholdRange's verification_attempts).
            fill_retry_margin: Extra packets to add to total when retrying
                fill verification. Compensates for Step2 being slightly off.
            drain_settle_delay: Seconds between tx_enable(dst_drain) and the
                first PAUSE counter sample. Allows drain to complete and
                PFC to react.
            pause_observation_window: Seconds between the two PAUSE counter
                samples in _drain_phase. Long enough to catch periodic PAUSE
                frames (xoff still active) but short enough to keep iteration
                time bounded. Default 0.1s — on TH2 7260CX3 physical
                validation, xoff produces ~220 pauses in this window
                (~2200 pauses/sec); xon produces ~0.
            pause_stop_tolerance: Max counter delta in the observation window
                that still counts as "stopped" (xon fired). Strictly-less-than
                comparison: a growth `< pause_stop_tolerance` is xon, a growth
                `>= pause_stop_tolerance` is xoff still active. Default 5
                means a growth of 0–4 is xon and 5+ is xoff — well below the
                ~220 observed during xoff on TH2 (~44x margin).
        """
        if pfcxoff_point is None or pfcxoff_point <= 0:
            raise ValueError(
                "PfcXonProbingExecutor requires a positive pfcxoff_point "
                "(obtained from prior PfcXoff point probe)."
            )
        if holder_port is None:
            raise ValueError(
                "PfcXonProbingExecutor requires holder_port "
                "(the dst port that holds buffer during the drain check)."
            )

        self.ptftest = ptftest
        self.observer = observer
        self.pfcxoff_point = int(pfcxoff_point)
        self.holder_port = int(holder_port)
        self.verbose = verbose
        self.name = name
        self.max_fill_attempts = max_fill_attempts
        self.fill_retry_margin = fill_retry_margin
        self.drain_settle_delay = drain_settle_delay
        self.pause_observation_window = pause_observation_window
        self.pause_stop_tolerance = pause_stop_tolerance

    # ------------------------------------------------------------------
    # Public API — conforms to ProbingExecutorProtocol (2-port interface).
    # holder_port is internalized via __init__.
    # ------------------------------------------------------------------

    def prepare(self, src_port: int, dst_port: int) -> None:
        """
        Prepare the 2-dst topology: drain residual buffer on both dst ports,
        then hold both (tx_disable) so the next fill phase starts clean.

        Args:
            src_port: source port (unused in prepare but required by protocol).
            dst_port: drain target port.
        """
        self.ptftest.buffer_ctrl.drain_buffer([dst_port, self.holder_port])
        time.sleep(PORT_TX_CTRL_DELAY)
        self.ptftest.buffer_ctrl.hold_buffer([dst_port, self.holder_port])
        time.sleep(PORT_TX_CTRL_DELAY)

        if self.verbose and self.observer:
            self.observer.trace(
                f"[PfcXon Executor] Prepare: src={src_port} drain={dst_port} "
                f"holder={self.holder_port} pfcxoff_point={self.pfcxoff_point}"
            )

    def check(
        self,
        src_port: int,
        dst_port: int,
        value: int,
        attempts: int = 1,
        drain_buffer: bool = True,
        iteration: int = 0,
        **traffic_keys,
    ) -> Tuple[bool, bool]:
        """
        Check if draining `value` packets from dst_port causes XOn to fire.

        Args:
            src_port: source port (single PG, single DSCP).
            dst_port: drain target — receives `value` packets in fill phase,
                then tx_enabled to drain.
            value: drain count D (how many packets we test as the XOn offset).
                Must satisfy 1 <= value <= pfcxoff_point.
            attempts: outer verification attempts (multiple full check cycles
                for noise resilience). Defaults to 1.
            drain_buffer: Accepted for protocol conformance but ignored — every
                check is always a full fill-then-drain cycle.
            iteration: Current iteration index (for observer reporting).
            **traffic_keys: traffic identification (must include pg=N).

        Returns:
            (success, xon_fired):
                success — True if check completed without inconsistency.
                xon_fired — True if XOn was triggered at this D.
        """
        assert self.observer is not None, "PfcXon executor requires an observer."

        if value < 1 or value > self.pfcxoff_point:
            if self.verbose:
                self.observer.trace(
                    f"[PfcXon Executor] check: value={value} out of range "
                    f"[1, {self.pfcxoff_point}]; returning (True, False)"
                )
            return True, False

        try:
            results = []

            for attempt in range(attempts):
                # ===== Phase 1: FILL =====
                fill_ok, baseline_pause_count = self._fill_phase(
                    src_port, dst_port, value, **traffic_keys
                )
                if not fill_ok:
                    # Could not reliably trigger xoff after retries — abort
                    if self.verbose:
                        self.observer.trace(
                            f"[PfcXon Executor] Fill verification FAILED at value={value} "
                            f"(could not trigger xoff after {self.max_fill_attempts} attempts)"
                        )
                    return False, False

                # ===== Phase 2: DRAIN =====
                xon_fired = self._drain_phase(
                    src_port, dst_port, baseline_pause_count
                )
                results.append(xon_fired)

                # ===== Phase 3: CLEANUP =====
                self._cleanup_phase(dst_port)

                if self.verbose:
                    self.observer.trace(
                        f"[PfcXon Executor] Verification {attempt + 1}/{attempts}: "
                        f"value={value}, xon_fired={xon_fired}"
                    )

            # ===== Result analysis =====
            if len(set(results)) > 1:
                # Inconsistent across attempts — fail the check
                return False, False
            return True, results[0]

        except Exception as e:
            if self.verbose and self.observer:
                self.observer.trace(
                    f"[PfcXon Executor] Check failed: value={value}, error={e}"
                )
            return False, False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_pause_count(self, src_port: int) -> int:
        """
        Read the current PFC PAUSE_RX counter for src_port at the
        configured PG index. Single seam between the executor and the
        underlying counter source — overridden by SimPfcXonProbingExecutor
        to read from a HardwareModel instead of SAI.
        """
        cnt, _ = sai_thrift_read_port_counters(
            self.ptftest.src_client,
            self.ptftest.asic_type,
            port_list["src"][src_port],
        )
        return cnt[self.ptftest.cnt_pg_idx]

    def _fill_phase(
        self,
        src_port: int,
        dst_port: int,
        value: int,
        **traffic_keys,
    ) -> Tuple[bool, int]:
        """
        Fill ingress buffer up to pfcxoff_point and verify xoff fires.

        Returns (success, baseline_pause_count_after_xoff_fires).
        Retries up to max_fill_attempts adding fill_retry_margin extra
        packets each retry to compensate for Step2 imprecision / noise.
        """
        holder_port = self.holder_port
        for attempt in range(self.max_fill_attempts):
            extra = attempt * self.fill_retry_margin
            pkts_to_drain = value
            pkts_to_holder = (self.pfcxoff_point - value) + extra

            # Reset state — drain everything, then hold both
            self.ptftest.buffer_ctrl.drain_buffer([dst_port, holder_port])
            time.sleep(PORT_TX_CTRL_DELAY)
            self.ptftest.buffer_ctrl.hold_buffer([dst_port, holder_port])
            time.sleep(PORT_TX_CTRL_DELAY)

            # Snapshot pre-fill PAUSE counter
            pre_pause = self._read_pause_count(src_port)

            # Send the two streams
            if pkts_to_drain > 0:
                self.ptftest.buffer_ctrl.send_traffic(
                    src_port, dst_port, pkts_to_drain, **traffic_keys
                )
            if pkts_to_holder > 0:
                self.ptftest.buffer_ctrl.send_traffic(
                    src_port, holder_port, pkts_to_holder, **traffic_keys
                )

            # Allow PFC counter to update
            time.sleep(PFC_TRIGGER_DELAY)

            # Did xoff fire?
            post_pause = self._read_pause_count(src_port)

            xoff_fired = post_pause > pre_pause
            if self.verbose:
                self.observer.trace(
                    f"[PfcXon Executor] Fill attempt {attempt + 1}/{self.max_fill_attempts}: "
                    f"drain={pkts_to_drain} holder={pkts_to_holder} (extra={extra}); "
                    f"PAUSE pre={pre_pause} post={post_pause} fired={xoff_fired}"
                )

            if xoff_fired:
                return True, post_pause

        return False, 0

    def _drain_phase(
        self,
        src_port: int,
        dst_port: int,
        baseline_pause_count: int,
    ) -> bool:
        """
        Open dst_port's tx so its queued packets drain. Detect XOn fire by
        observing whether the PFC PAUSE counter STOPS incrementing.

        Background: while buffer is in xoff state, DUT periodically (~every
        450µs per IEEE 802.1Qbb in standard 802.3x mode, ~2200 pauses/sec
        on TH2 7260CX3 — see top-of-file NOTE for measured rate) emits PFC
        PAUSE frames, so the pause counter increments continuously. If we
        drain past xon threshold, PFC releases and PAUSE frames stop ->
        counter freezes.

        Note: the fill phase sends a bounded burst of pfcxoff_point packets,
        not a continuous stream. After xon fires there is no source-side
        refill that would re-trigger xoff, so the counter simply stops.

        Args:
            src_port: source port — pause counter is read here.
            dst_port: drain target — opened (tx_enable) to release D
                queued packets.
            baseline_pause_count: post-fill PAUSE count (for trace logging
                and consistency checks; the new logic does not use it for
                the xon decision — see class docstring step 7).

        Returns:
            True if PAUSE counter has effectively stopped incrementing
            within the observation window (delta < pause_stop_tolerance).
        """
        self.ptftest.buffer_ctrl.drain_buffer([dst_port])
        time.sleep(self.drain_settle_delay)

        # Sample 1: just after drain settles.
        pause_t1 = self._read_pause_count(src_port)

        # Wait observation window for periodic PAUSE frames to register
        # (if any are still being sent).
        time.sleep(self.pause_observation_window)

        # Sample 2: end of observation window.
        pause_t2 = self._read_pause_count(src_port)

        pause_growth = pause_t2 - pause_t1
        xon_fired = pause_growth < self.pause_stop_tolerance

        # Diagnostic: pauses accumulated during drain_settle_delay
        # (= pause_t1 - baseline_pause_count). If xon fires correctly, this
        # measures PAUSE residual after drain (helps OQ2 investigation —
        # tuning drain_settle_delay if residual > expected).
        settle_growth = pause_t1 - baseline_pause_count

        if self.verbose and self.observer:
            # Use console() (writes to stderr with immediate flush) instead
            # of trace() (logging.info, may be buffered). This guarantees
            # the per-iteration diagnostic survives PTF /tmp log truncation
            # or SIGKILL — important for OQ2 investigation where we need
            # the full D=1..max_iter sweep on physical hardware.
            self.observer.console(
                f"[PfcXon Executor] Drain check: baseline={baseline_pause_count} "
                f"settle_growth={settle_growth} pause_t1={pause_t1} pause_t2={pause_t2} "
                f"window_growth={pause_growth} tolerance={self.pause_stop_tolerance} "
                f"window={self.pause_observation_window}s xon_fired={xon_fired}"
            )

        return xon_fired

    def _cleanup_phase(self, dst_port: int) -> None:
        """Drain everything and reset both dst ports for next iteration."""
        self.ptftest.buffer_ctrl.drain_buffer([dst_port, self.holder_port])
        time.sleep(PORT_TX_CTRL_DELAY)
