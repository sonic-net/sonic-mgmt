"""
PFC XOn Probing Executor — 2-dst topology with fill+drain protocol

Detects pkts_num_dismiss_pfc + pkts_num_hysteresis (XOn offset) using
"drain after xoff" protocol:
  - fill phase: send packets via 2 flows (src->dst_A, src->dst_B) so they
    accumulate at the SAME ingress PG (same source port + same DSCP).
    Total = pfcxoff_point. Verify PFC_PAUSE_RX incremented (xoff fired).
  - drain phase: tx_enable(dst_A) drains its portion. Wait. If buffer
    level fell past xon threshold, src is resumed -> sends more -> next
    xoff fires -> PFC_PAUSE_RX increments AGAIN.
  - decision: PAUSE counter incremented past baseline+1 = xon resumed.

Differs from PfcXoffProbingExecutor:
  - Takes (src, dst_A, dst_B) instead of (src, dst).
  - check(D) means: with D packets routed to dst_A and (pfcxoff_point-D)
    routed to dst_B, after opening dst_A's tx, did xon fire?
  - Returns (success, xon_fired).

Reference: legacy PFCXonTest (sai_qos_tests.py L2868) which uses 3-port
fan-out and compares pkts_num_dismiss_pfc + hysteresis offset.

Usage:
    executor = PfcXonProbingExecutor(
        ptftest=self,
        observer=observer,
        pfcxoff_point=N,        # known from prior PfcXoff probe
        verbose=True,
    )
    executor.prepare(src, dst_A, dst_B)
    success, xon_fired = executor.check(src, dst_A, dst_B, value=D, **traffic_keys)
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

    Topology: 1 src -> 2 dst (dst_A is drain target, dst_B is the holder).
    Both dst flows enter the SAME ingress PG (same source port + same DSCP).

    Protocol divergence from peer executors (intentional):
      Peer executors (PfcXoffProbingExecutor, IngressDropProbingExecutor,
      Sim*ProbingExecutor) use `check(src_port, dst_port, value, ...)` — 2 ports.
      This executor uses `check(src_port, dst_port_a, dst_port_b, value, ...)` —
      3 ports. The divergence is required because XOn is a fill-then-drain protocol
      that needs two destination queues: dst_A is drained to test the XOn trigger
      while dst_B holds back its share of the buffer fill. Algorithms paired with
      this executor (XonDrainStepAlgorithm, XonDrainBinaryAlgorithm) are aware
      of and use the 3-port signature explicitly.

    The constructor takes pfcxoff_point obtained from a prior PfcXoff probe
    so the executor knows the buffer fill level needed to trigger xoff.

    The check(value=D) logic:
      1. tx_disable both dst_A, dst_B
      2. drain residual buffer
      3. send D packets via flow(src->dst_A); send (pfcxoff_point - D) via
         flow(src->dst_B). Total = pfcxoff_point. xoff fires.
      4. (verify) read PFC_PAUSE_RX baseline. If not incremented from
         pre-fill snapshot, retry up to MAX_FILL_ATTEMPTS with margin.
      5. tx_enable(dst_A) -> drain D packets out
      6. wait DRAIN_SETTLE_DELAY (let buffer settle and PFC react)
      7. sample PFC_PAUSE_RX twice over PAUSE_OBSERVATION_WINDOW.
         - If counter delta < PAUSE_STOP_TOLERANCE => PFC has released
           (xon fired). Return (True, True).
         - Else (counter still incrementing because PFC is still asserted)
           => xon NOT fired at this D. Return (True, False).
      8. cleanup: tx_enable(dst_B) so next iteration has clean state.

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
            verbose: Enable trace output.
            name: Identifier for this executor instance (e.g., "step3_drain").
            max_fill_attempts: How many times to retry fill if xoff doesn't
                fire (noise tolerance, like ThresholdRange's verification_attempts).
            fill_retry_margin: Extra packets to add to total when retrying
                fill verification. Compensates for Step2 being slightly off.
            drain_settle_delay: Seconds between tx_enable(dst_A) and the
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

        self.ptftest = ptftest
        self.observer = observer
        self.pfcxoff_point = int(pfcxoff_point)
        self.verbose = verbose
        self.name = name
        self.max_fill_attempts = max_fill_attempts
        self.fill_retry_margin = fill_retry_margin
        self.drain_settle_delay = drain_settle_delay
        self.pause_observation_window = pause_observation_window
        self.pause_stop_tolerance = pause_stop_tolerance

    # ------------------------------------------------------------------
    # Public API — matches ProbingExecutorProtocol shape (with 2 dst ports
    # passed as positional args; algorithms designed for XOn explicitly
    # use this signature)
    # ------------------------------------------------------------------

    def prepare(self, src_port: int, dst_port_a: int, dst_port_b: int) -> None:
        """
        Prepare the 2-dst topology: drain residual buffer on both dst ports,
        then hold both (tx_disable) so the next fill phase starts clean.
        """
        self.ptftest.buffer_ctrl.drain_buffer([dst_port_a, dst_port_b])
        time.sleep(PORT_TX_CTRL_DELAY)
        self.ptftest.buffer_ctrl.hold_buffer([dst_port_a, dst_port_b])
        time.sleep(PORT_TX_CTRL_DELAY)

        if self.verbose and self.observer:
            self.observer.trace(
                f"[PfcXon Executor] Prepare: src={src_port} dst_A={dst_port_a} "
                f"dst_B={dst_port_b} pfcxoff_point={self.pfcxoff_point}"
            )

    def check(
        self,
        src_port: int,
        dst_port_a: int,
        dst_port_b: int,
        value: int,
        attempts: int = 1,
        **traffic_keys,
    ) -> Tuple[bool, bool]:
        """
        Check if draining `value` packets from dst_A causes XOn to fire.

        Args:
            src_port: source port (single PG, single DSCP).
            dst_port_a: drain target — receives `value` packets in fill phase,
                then tx_enabled to drain.
            dst_port_b: holder — receives (pfcxoff_point - value) packets;
                stays tx_disabled during the check.
            value: drain count D (how many packets we test as the XOn offset).
                Must satisfy 1 <= value <= pfcxoff_point.
            attempts: outer verification attempts (multiple full check cycles
                for noise resilience). Defaults to 1.
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
                    src_port, dst_port_a, dst_port_b, value, **traffic_keys
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
                    src_port, dst_port_a, baseline_pause_count
                )
                results.append(xon_fired)

                # ===== Phase 3: CLEANUP =====
                self._cleanup_phase(dst_port_a, dst_port_b)

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

    def _fill_phase(
        self,
        src_port: int,
        dst_port_a: int,
        dst_port_b: int,
        value: int,
        **traffic_keys,
    ) -> Tuple[bool, int]:
        """
        Fill ingress buffer up to pfcxoff_point and verify xoff fires.

        Returns (success, baseline_pause_count_after_xoff_fires).
        Retries up to max_fill_attempts adding fill_retry_margin extra
        packets each retry to compensate for Step2 imprecision / noise.
        """
        for attempt in range(self.max_fill_attempts):
            extra = attempt * self.fill_retry_margin
            pkts_to_a = value
            pkts_to_b = (self.pfcxoff_point - value) + extra

            # Reset state — drain everything, then hold both
            self.ptftest.buffer_ctrl.drain_buffer([dst_port_a, dst_port_b])
            time.sleep(PORT_TX_CTRL_DELAY)
            self.ptftest.buffer_ctrl.hold_buffer([dst_port_a, dst_port_b])
            time.sleep(PORT_TX_CTRL_DELAY)

            # Snapshot pre-fill PAUSE counter
            pre_cnt, _ = sai_thrift_read_port_counters(
                self.ptftest.src_client,
                self.ptftest.asic_type,
                port_list["src"][src_port],
            )
            pre_pause = pre_cnt[self.ptftest.cnt_pg_idx]

            # Send the two streams
            if pkts_to_a > 0:
                self.ptftest.buffer_ctrl.send_traffic(
                    src_port, dst_port_a, pkts_to_a, **traffic_keys
                )
            if pkts_to_b > 0:
                self.ptftest.buffer_ctrl.send_traffic(
                    src_port, dst_port_b, pkts_to_b, **traffic_keys
                )

            # Allow PFC counter to update
            time.sleep(PFC_TRIGGER_DELAY)

            # Did xoff fire?
            post_cnt, _ = sai_thrift_read_port_counters(
                self.ptftest.src_client,
                self.ptftest.asic_type,
                port_list["src"][src_port],
            )
            post_pause = post_cnt[self.ptftest.cnt_pg_idx]

            xoff_fired = post_pause > pre_pause
            if self.verbose:
                self.observer.trace(
                    f"[PfcXon Executor] Fill attempt {attempt + 1}/{self.max_fill_attempts}: "
                    f"A={pkts_to_a} B={pkts_to_b} (extra={extra}); "
                    f"PAUSE pre={pre_pause} post={post_pause} fired={xoff_fired}"
                )

            if xoff_fired:
                return True, post_pause

        return False, 0

    def _drain_phase(
        self,
        src_port: int,
        dst_port_a: int,
        baseline_pause_count: int,
    ) -> bool:
        """
        Open dst_A's tx so its queued packets drain. Detect XOn fire by
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
            dst_port_a: drain target — opened (tx_enable) to release D
                queued packets.
            baseline_pause_count: post-fill PAUSE count (for trace logging
                and consistency checks; the new logic does not use it for
                the xon decision — see class docstring step 7).

        Returns:
            True if PAUSE counter has effectively stopped incrementing
            within the observation window (delta < pause_stop_tolerance).
        """
        self.ptftest.buffer_ctrl.drain_buffer([dst_port_a])
        time.sleep(self.drain_settle_delay)

        # Sample 1: just after drain settles.
        cnt1, _ = sai_thrift_read_port_counters(
            self.ptftest.src_client,
            self.ptftest.asic_type,
            port_list["src"][src_port],
        )
        pause_t1 = cnt1[self.ptftest.cnt_pg_idx]

        # Wait observation window for periodic PAUSE frames to register
        # (if any are still being sent).
        time.sleep(self.pause_observation_window)

        # Sample 2: end of observation window.
        cnt2, _ = sai_thrift_read_port_counters(
            self.ptftest.src_client,
            self.ptftest.asic_type,
            port_list["src"][src_port],
        )
        pause_t2 = cnt2[self.ptftest.cnt_pg_idx]

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

    def _cleanup_phase(self, dst_port_a: int, dst_port_b: int) -> None:
        """Drain everything and reset both dst ports for next iteration."""
        self.ptftest.buffer_ctrl.drain_buffer([dst_port_a, dst_port_b])
        time.sleep(PORT_TX_CTRL_DELAY)
