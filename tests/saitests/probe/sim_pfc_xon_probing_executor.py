#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sim PFC XOn Executor - Simulated PFC release behavior for testing

Reference companion of PfcXonProbingExecutor that drives a HardwareModel
instead of real SAI counters. Lets algorithm convergence be exercised
without physical hardware via:

    from executor_registry import ExecutorRegistry

    executor = ExecutorRegistry.create(
        'pfc_xon', 'sim',
        observer=obs,
        pfcxoff_point=8800,
        true_xon_offset=13,
        holder_port=2,
    )
    # Standard 2-port algorithm interface:
    algo = ThresholdPointProbingAlgorithm(executor=executor, always_full_cycle=True, ...)
    algo.run(src=0, dst=1, pg=3)

Drift-zero design (per drain-bug post-mortem 2026-05-08):
  Inherits real PfcXonProbingExecutor and overrides ONLY the
  _read_pause_count seam. All algorithm-relevant code (fill phase, drain
  phase, counter-stop detection, fill retries, cleanup) is the SAME code
  that runs in physical. If anyone changes the real executor's algorithm,
  sim follows automatically -- no parallel implementation to drift.

  Compare to SimPfcXoffProbingExecutor (sibling): that one re-implements
  check() as a pure threshold compare (`value >= actual_threshold`).
  XOn's physics (counter-stop detection over an observation window) is
  too intricate to safely re-implement, hence the "single seam override"
  approach instead.

The HardwareModel below is the simulation substrate: a stateful counter
that emits PAUSE pumps periodically while in xoff (matching real DUT
IEEE 802.1Qbb behavior, ~2200 pauses/sec on TH2 7260CX3) and freezes
when buffer drains past true_xon_offset.
"""

from unittest.mock import MagicMock

from executor_registry import ExecutorRegistry
from pfc_xon_probing_executor import PfcXonProbingExecutor


class HardwareModel:
    """
    Stateful PFC_PAUSE_RX counter model.

    MODEL FIDELITY (per code review I4 + drain-bug fix 2026-05-08):
    Uses ADDITIVE drain semantics -- XOn fires when total_drained >=
    true_xon_offset. Real ASIC behavior is OCCUPANCY-CROSSING (XOn fires
    when buffer occupancy drops below pfcxoff_point - xon_offset). The
    two are equivalent only for the perfectly clean fill-then-drain-once
    scenario tested here. The model is fine for validating algorithm
    logic + counter-read ordering, but it does NOT model overshoot
    semantics, multi-drain accumulation, or counter update latency.
    Physical validation remains required.

    Models a single ingress PG with:
      - pfcxoff_point: how many packets fill the buffer to xoff threshold.
      - true_xon_offset: how many packets must drain after xoff for xon
          to fire.
      - Internal state: queues per dst port, pause_counter, _in_xoff flag.

    Methods called by the executor (via patches in IT, or via sim's
    pre-wired ptftest stub here):
      - send_traffic(src, dst, pkts, **kw): pkts go to the dst's queue;
          also increase total ingress occupancy.
      - drain_buffer(ports): remove all queued packets from those ports'
          egress queue (effectively empties their egress buffer; ingress
          usage drops by their queue depth).
      - hold_buffer(ports): tx_disable; queue stays.
      - read_counter(): returns (counters, queue_counters) where
          counters[cnt_pg_idx] = pause_counter.

    XOff trigger logic:
      When ingress buffer >= pfcxoff_point AND not yet in xoff state,
      increment pause_counter once (the "first xoff fire" event) and set
      _in_xoff = True.

    Periodic PAUSE emission (drain-bug fix 2026-05-08):
      While _in_xoff is True, every call to read_counter() increments
      pause_counter by `pause_rate_per_read`. This models the real
      DUT behavior -- IEEE 802.1Qbb specifies PAUSE frames are emitted
      periodically (~every 100us) for as long as xoff is asserted, so
      the counter naturally accumulates pauses over time. The new
      _drain_phase logic relies on this: it reads the counter twice
      with an observation_window between them and detects xon by
      observing the counter STOP incrementing (delta < tolerance).

    XOn trigger logic (additive -- see disclaimer above):
      After xoff, if cumulative drain count >= true_xon_offset, set
      _in_xoff = False. The counter freezes -- no more pauses emitted --
      which is what the new _drain_phase detects.
    """

    def __init__(self, pfcxoff_point: int, true_xon_offset: int,
                 cnt_pg_idx: int = 5, pause_rate_per_read: int = 10):
        self.pfcxoff_point = pfcxoff_point
        self.true_xon_offset = true_xon_offset
        self.cnt_pg_idx = cnt_pg_idx
        self.pause_counter = 0
        self.queues = {}    # port_id -> queued packets
        self.tx_disabled = set()
        self._in_xoff = False
        # Per-read PAUSE counter increment while in xoff. Default 10
        # ensures delta in the executor's 2-sample window exceeds the
        # default pause_stop_tolerance of 5. Real-hw measured ~40 pauses
        # per 100ms window on TH2 7260CX3.
        self.pause_rate_per_read = pause_rate_per_read

    def send_traffic(self, src_port, dst_port, pkts, **traffic_keys):
        """Add pkts to dst's queue. If total ingress >= xoff_point, fire
        xoff (one-time event)."""
        # Treat src_port as identifier; only count buffer at dst level.
        self.queues.setdefault(dst_port, 0)
        self.queues[dst_port] += pkts

        total = sum(self.queues.values())
        # XOff fires the FIRST time total crosses pfcxoff_point upward.
        # Subsequent reads (while still in xoff) will pump the counter via
        # read_counter's periodic-pause modeling.
        if total >= self.pfcxoff_point and not self._in_xoff:
            self.pause_counter += 1
            self._in_xoff = True

    def drain_buffer(self, ports):
        """Drain (tx_enable + flush) the listed ports.

        For each port, snapshot its queue depth, clear it, and check if
        the resulting drop crosses the xon threshold. If yes, set
        _in_xoff = False (PFC released, pauses stop). The counter is NOT
        incremented here -- this is the key change from the original
        buggy model. See class docstring "XOn trigger logic" for
        rationale.
        """
        if not isinstance(ports, list):
            ports = [ports]

        # Track xoff state at entry; xon-crossing requires we WERE in xoff.
        was_in_xoff = self._in_xoff

        total_drained = 0
        for p in ports:
            q = self.queues.pop(p, 0)
            total_drained += q

        if was_in_xoff and total_drained >= self.true_xon_offset:
            # Buffer dropped past xon threshold -> PFC releases, periodic
            # PAUSE stream stops. Counter freezes (no +1 here, unlike the
            # original buggy model).
            self._in_xoff = False

        # If we drained EVERYTHING from queues, also clear xoff state
        # (so next fill cycle starts fresh).
        if not self.queues:
            self._in_xoff = False

    def hold_buffer(self, ports):
        """tx_disable. We don't need to model this explicitly -- packets
        accumulate in queue regardless."""
        if not isinstance(ports, list):
            ports = [ports]
        self.tx_disabled.update(ports)

    def read_counter(self):
        """Return (counters, queue_counters) tuple. counters[cnt_pg_idx]
        is the pause counter. While in xoff, increment the counter on
        every read to model periodic PFC PAUSE emission."""
        if self._in_xoff:
            self.pause_counter += self.pause_rate_per_read
        counters = [0] * 20
        counters[self.cnt_pg_idx] = self.pause_counter
        return counters, [0] * 10


def make_ptftest_with_hw(hw_model):
    """Wire a HardwareModel up as the ptftest's buffer_ctrl source.

    Returns a MagicMock ptftest stub the real executor can drive; all
    relevant attributes (asic_type, src_client, cnt_pg_idx) and
    buffer_ctrl methods (send_traffic, drain_buffer, hold_buffer) point
    at the HardwareModel.
    """
    ptf = MagicMock()
    ptf.cnt_pg_idx = hw_model.cnt_pg_idx
    ptf.asic_type = "mock"
    ptf.src_client = MagicMock()

    ptf.buffer_ctrl = MagicMock()
    ptf.buffer_ctrl.send_traffic.side_effect = hw_model.send_traffic
    ptf.buffer_ctrl.drain_buffer.side_effect = hw_model.drain_buffer
    ptf.buffer_ctrl.hold_buffer.side_effect = hw_model.hold_buffer

    return ptf


@ExecutorRegistry.register(probe_type='pfc_xon', executor_env='sim')
class SimPfcXonProbingExecutor(PfcXonProbingExecutor):
    """
    Sim PfcXon executor -- runs the real algorithm against a HardwareModel.

    Inherits PfcXonProbingExecutor and overrides ONLY _read_pause_count to
    bypass SAI and read from the in-memory HardwareModel. All other code
    paths (fill phase, drain phase, retry logic, cleanup) execute the
    SAME real-hardware code, so this sim is drift-free by construction.

    Required kwargs:
      - observer: ProbingObserver instance.
      - pfcxoff_point: int, fill threshold.
      - true_xon_offset: int, the answer the algorithm should converge to.

    Optional kwargs:
      - pause_rate_per_read: int (default 10), PAUSE counter increment
          per read while in xoff. Must exceed pause_stop_tolerance for
          the executor to detect "still in xoff".
      - cnt_pg_idx: int (default 5), priority group index.
      - ptftest: optional pre-built ptftest stub. If None, one is
          auto-built via make_ptftest_with_hw(self.hw_model).
      - any kwargs accepted by PfcXonProbingExecutor (verbose, name,
          max_fill_attempts, fill_retry_margin, drain_settle_delay,
          pause_observation_window, pause_stop_tolerance).
    """

    def __init__(self, observer, name="", pfcxoff_point=None,
                 true_xon_offset=None, holder_port=None, ptftest=None,
                 pause_rate_per_read=10, cnt_pg_idx=5, **kwargs):
        if true_xon_offset is None:
            raise ValueError(
                "SimPfcXonProbingExecutor requires true_xon_offset "
                "(the answer the algorithm should converge to)."
            )
        # Default holder_port for sim — callers may override
        if holder_port is None:
            holder_port = 99

        self.hw_model = HardwareModel(
            pfcxoff_point=pfcxoff_point,
            true_xon_offset=true_xon_offset,
            cnt_pg_idx=cnt_pg_idx,
            pause_rate_per_read=pause_rate_per_read,
        )
        if ptftest is None:
            ptftest = make_ptftest_with_hw(self.hw_model)

        super().__init__(
            ptftest=ptftest,
            observer=observer,
            pfcxoff_point=pfcxoff_point,
            holder_port=holder_port,
            name=name,
            **kwargs,
        )

        # Sim-side coupling guard (per code review S5, 2026-05-09; tightened
        # per r2 N1, 2026-05-09): the HardwareModel must increment the counter
        # by STRICTLY MORE than the executor's pause_stop_tolerance per read,
        # so that during xoff the 2-sample observation window's growth (=
        # pause_rate_per_read for the one read between t1 and t2) exceeds
        # tolerance and the executor correctly reads "still in xoff".
        #
        # Strict `<` matches the executor's xon_fired predicate
        # (pfc_xon_probing_executor.py: `xon_fired = pause_growth <
        # self.pause_stop_tolerance`). At the boundary rate == tolerance,
        # `growth < tolerance` is False -> "still in xoff" (correct), so
        # rate == tolerance is technically safe; but matching the exact
        # comparison removes the ambiguity. Catch the misconfiguration at
        # construction rather than reading silently-wrong test results.
        if self.hw_model.pause_rate_per_read < self.pause_stop_tolerance:
            raise ValueError(
                f"HardwareModel.pause_rate_per_read={self.hw_model.pause_rate_per_read} "
                f"must be >= executor.pause_stop_tolerance={self.pause_stop_tolerance}; "
                "otherwise sim cannot model 'still in xoff' correctly."
            )

    def _read_pause_count(self, src_port: int) -> int:
        """Single seam override: read from HardwareModel instead of SAI.

        src_port is ignored -- the model has a single PG and tracks a
        single pause counter.
        """
        cnt, _ = self.hw_model.read_counter()
        return cnt[self.hw_model.cnt_pg_idx]
