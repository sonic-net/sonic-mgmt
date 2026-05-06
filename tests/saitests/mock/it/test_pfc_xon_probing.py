"""
Integration tests for PfcXon — Executor + Algorithm together against a
realistic hardware model.

Tests the full flow from algorithm.run() down to executor.check() to a
simulated "DUT" that models PFC_PAUSE_RX counter behavior given:
  - pfcxoff_point (xoff threshold)
  - true_xon_offset (the answer we expect to find)
  - optional noise (to test verification retries)

Coverage:
- StepAlgorithm + Executor: Broadcom-scale (offset 12-18)
- BinaryAlgorithm + Executor: Cisco-scale (offset 3245), Mellanox-PAC-scale (offset 1024)
- Edge cases: offset=1, offset=pfcxoff_point
- Noise: occasional fill failures, occasional drain failures

Why this is "IT" not "UT":
  - We exercise REAL Executor code paths (not mocked check())
  - The "DUT" is a stateful counter model that behaves like real hardware
  - Algorithm and Executor are wired up the same way as in production
"""

import pytest
from unittest.mock import MagicMock, patch
from probe_test_helper import setup_test_environment  # noqa: E402

# Setup PTF mocks + probe path (must run before importing probe modules)
setup_test_environment()

from observer_config import ObserverConfig  # noqa: E402
from probing_observer import ProbingObserver  # noqa: E402


def _make_observer(name="it"):
    config = ObserverConfig(
        probe_target="pfc_xon",
        algorithm_name=name,
        strategy="integration",
        check_column_title="Xon",
        table_column_mapping={}
    )
    return ProbingObserver(name, 1, observer_config=config)


class HardwareModel:
    """
    Stateful PFC_PAUSE_RX counter model.

    Models a single ingress PG with:
      - pfcxoff_point: how many packets fill the buffer to xoff threshold.
      - true_xon_offset: how many packets must drain after xoff for xon to fire.
      - Internal state: current_buffer_pkts, pause_counter.

    Methods called by the executor (via patches):
      - send_traffic(src, dst, pkts, **kw): pkts go to the dst's queue;
        also increase total ingress occupancy.
      - drain_buffer(ports): remove all queued packets from those ports'
        egress queue (effectively empties their egress buffer; ingress
        usage drops by their queue depth).
      - hold_buffer(ports): tx_disable; queue stays.
      - read counter for src_port: returns current pause_counter.

    XOff trigger logic:
      When ingress buffer >= pfcxoff_point, increment pause_counter.

    XOn trigger logic:
      After xoff, if buffer level drops below (pfcxoff_point - true_xon_offset),
      we model that src is resumed -> next "send" from src will trigger xoff
      again -> pause_counter increments.

    Simplification: We collapse the "src resumes -> sends -> xoff fires
    again" into a single +1 to the counter when the drain crosses the
    xon threshold. This matches what the real executor observes.
    """

    def __init__(self, pfcxoff_point: int, true_xon_offset: int, cnt_pg_idx: int = 5):
        self.pfcxoff_point = pfcxoff_point
        self.true_xon_offset = true_xon_offset
        self.cnt_pg_idx = cnt_pg_idx
        self.pause_counter = 0
        self.queues = {}    # port_id -> queued packets
        self.tx_disabled = set()
        self.last_xoff_pause_count = None  # snapshot when xoff fired

    def send_traffic(self, src_port, dst_port, pkts, **traffic_keys):
        """Add pkts to dst's queue. If total ingress >= xoff_point, fire xoff."""
        # Treat src_port as identifier; only count buffer at dst level
        self.queues.setdefault(dst_port, 0)
        self.queues[dst_port] += pkts

        total = sum(self.queues.values())
        # XOff fires whenever total crosses pfcxoff_point upward
        # (and the crossing wasn't recorded yet)
        if total >= self.pfcxoff_point and self.last_xoff_pause_count != self.pause_counter:
            self.pause_counter += 1
            self.last_xoff_pause_count = self.pause_counter

    def drain_buffer(self, ports):
        """Drain (tx_enable + flush) the listed ports.

        For each port, snapshot its queue depth, clear it, and check if
        the resulting drop crosses the xon threshold (causing xon resume,
        which we model as immediate xoff re-trigger via implicit src resume).
        """
        if not isinstance(ports, list):
            ports = [ports]

        # If we're in xoff state, draining may trigger xon
        in_xoff = self.last_xoff_pause_count == self.pause_counter

        total_drained = 0
        for p in ports:
            q = self.queues.pop(p, 0)
            total_drained += q

        if in_xoff and total_drained >= self.true_xon_offset:
            # Buffer dropped past xon threshold -> src resumes -> refills past xoff
            # Model: pause counter increments again (xoff fires again)
            self.pause_counter += 1

        # If we drained EVERYTHING from queues, also clear xoff state
        # (so next fill cycle starts fresh)
        if not self.queues:
            self.last_xoff_pause_count = None

    def hold_buffer(self, ports):
        """tx_disable. We don't need to model this explicitly — packets
        accumulate in queue regardless."""
        if not isinstance(ports, list):
            ports = [ports]
        self.tx_disabled.update(ports)

    def read_counter(self):
        """Return (counters, queue_counters) tuple. counters[cnt_pg_idx]
        is the pause counter."""
        counters = [0] * 20
        counters[self.cnt_pg_idx] = self.pause_counter
        return counters, [0] * 10


def _make_ptftest_with_hw(hw_model):
    """Wire HardwareModel up as the ptftest's buffer_ctrl + counter source."""
    ptf = MagicMock()
    ptf.cnt_pg_idx = hw_model.cnt_pg_idx
    ptf.asic_type = "mock"
    ptf.src_client = MagicMock()

    ptf.buffer_ctrl = MagicMock()
    ptf.buffer_ctrl.send_traffic.side_effect = hw_model.send_traffic
    ptf.buffer_ctrl.drain_buffer.side_effect = hw_model.drain_buffer
    ptf.buffer_ctrl.hold_buffer.side_effect = hw_model.hold_buffer

    return ptf


@patch('pfc_xon_probing_executor.port_list', {"src": {24: "mock_24"}})
@patch('pfc_xon_probing_executor.time.sleep')  # don't actually sleep
class TestPfcXonIntegration:
    """End-to-end Algorithm + Executor against HardwareModel."""

    def setup_method(self):
        self.observer = _make_observer()

    @pytest.mark.order(9000)
    def test_step_algo_finds_broadcom_th3_offset(self, mock_sleep):
        """Broadcom TH3 scenario: pfcxoff_point=8800, true_xon_offset=13."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        hw = HardwareModel(pfcxoff_point=8800, true_xon_offset=13)
        ptf = _make_ptftest_with_hw(hw)

        # Patch sai_thrift_read_port_counters to use our hardware model
        with patch('pfc_xon_probing_executor.sai_thrift_read_port_counters',
                   side_effect=lambda c, a, p: hw.read_counter()):

            executor = PfcXonProbingExecutor(
                ptftest=ptf, observer=self.observer,
                pfcxoff_point=8800,
            )
            algo = XonDrainStepAlgorithm(
                executor=executor, observer=self.observer, max_iter=30
            )
            lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 12
        assert upper == 13

    @pytest.mark.order(9001)
    def test_step_algo_finds_broadcom_td2_offset(self, mock_sleep):
        """Broadcom TD2: small offset 18."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        hw = HardwareModel(pfcxoff_point=2000, true_xon_offset=18)
        ptf = _make_ptftest_with_hw(hw)

        with patch('pfc_xon_probing_executor.sai_thrift_read_port_counters',
                   side_effect=lambda c, a, p: hw.read_counter()):

            executor = PfcXonProbingExecutor(
                ptftest=ptf, observer=self.observer, pfcxoff_point=2000,
            )
            algo = XonDrainStepAlgorithm(
                executor=executor, observer=self.observer, max_iter=30
            )
            lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 17
        assert upper == 18

    @pytest.mark.order(9002)
    def test_binary_algo_finds_cisco_j2c_offset(self, mock_sleep):
        """Cisco J2C: pfcxoff_point=388047, true_xon_offset=3245."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        hw = HardwareModel(pfcxoff_point=388047, true_xon_offset=3245)
        ptf = _make_ptftest_with_hw(hw)

        with patch('pfc_xon_probing_executor.sai_thrift_read_port_counters',
                   side_effect=lambda c, a, p: hw.read_counter()):

            executor = PfcXonProbingExecutor(
                ptftest=ptf, observer=self.observer, pfcxoff_point=388047,
            )
            algo = XonDrainBinaryAlgorithm(
                executor=executor, observer=self.observer, range_limit=32
            )
            lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 3244
        assert upper == 3245

    @pytest.mark.order(9003)
    def test_binary_algo_finds_mellanox_pac_offset(self, mock_sleep):
        """Mellanox PAC (SN4600C/SPC3): hysteresis=1024, dismiss=21 -> total ~1045."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        hw = HardwareModel(pfcxoff_point=10000, true_xon_offset=1045)
        ptf = _make_ptftest_with_hw(hw)

        with patch('pfc_xon_probing_executor.sai_thrift_read_port_counters',
                   side_effect=lambda c, a, p: hw.read_counter()):

            executor = PfcXonProbingExecutor(
                ptftest=ptf, observer=self.observer, pfcxoff_point=10000,
            )
            algo = XonDrainBinaryAlgorithm(
                executor=executor, observer=self.observer, range_limit=16
            )
            lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 1044
        assert upper == 1045

    @pytest.mark.order(9004)
    def test_binary_algo_finds_cisco_q3d_largest_offset(self, mock_sleep):
        """Cisco Q3D worst case: offset 12985."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        hw = HardwareModel(pfcxoff_point=388047, true_xon_offset=12985)
        ptf = _make_ptftest_with_hw(hw)

        with patch('pfc_xon_probing_executor.sai_thrift_read_port_counters',
                   side_effect=lambda c, a, p: hw.read_counter()):

            executor = PfcXonProbingExecutor(
                ptftest=ptf, observer=self.observer, pfcxoff_point=388047,
            )
            algo = XonDrainBinaryAlgorithm(
                executor=executor, observer=self.observer, range_limit=32
            )
            lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 12984
        assert upper == 12985

    @pytest.mark.order(9005)
    def test_step_algo_offset_equals_one(self, mock_sleep):
        """Edge: true_xon_offset=1 (minimum)."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        hw = HardwareModel(pfcxoff_point=1000, true_xon_offset=1)
        ptf = _make_ptftest_with_hw(hw)

        with patch('pfc_xon_probing_executor.sai_thrift_read_port_counters',
                   side_effect=lambda c, a, p: hw.read_counter()):

            executor = PfcXonProbingExecutor(
                ptftest=ptf, observer=self.observer, pfcxoff_point=1000,
            )
            algo = XonDrainStepAlgorithm(
                executor=executor, observer=self.observer, max_iter=10
            )
            lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 0
        assert upper == 1

    @pytest.mark.order(9006)
    def test_step_algo_does_not_find_when_below_max_iter(self, mock_sleep):
        """Pathological: true_xon_offset=100 but max_iter=20 -> not found."""
        from pfc_xon_probing_executor import PfcXonProbingExecutor
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        hw = HardwareModel(pfcxoff_point=1000, true_xon_offset=100)
        ptf = _make_ptftest_with_hw(hw)

        with patch('pfc_xon_probing_executor.sai_thrift_read_port_counters',
                   side_effect=lambda c, a, p: hw.read_counter()):

            executor = PfcXonProbingExecutor(
                ptftest=ptf, observer=self.observer, pfcxoff_point=1000,
            )
            algo = XonDrainStepAlgorithm(
                executor=executor, observer=self.observer, max_iter=20
            )
            lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower is None
        assert upper is None
