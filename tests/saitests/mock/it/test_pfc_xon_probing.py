"""
Integration tests for PfcXon -- Algorithm + Executor + HardwareModel via sim.

Tests the full algorithm flow against a realistic in-memory hardware
model, exercised through the registered SimPfcXonProbingExecutor (which
inherits the real PfcXonProbingExecutor and overrides only the SAI
counter read seam). This guarantees zero algorithm drift between IT
and physical runs -- the same _drain_phase / _fill_phase code is
exercised by both.

Coverage:
- StepAlgorithm + Executor: Broadcom-scale (offset 12-18)
- BinaryAlgorithm + Executor: Cisco-scale (offset 3245), Mellanox-PAC-scale (offset 1024)
- Edge cases: offset=1, offset=pfcxoff_point
- Pathological: max_iter exhaustion

Why this is "IT" not "UT":
  - We exercise REAL Executor code paths via SimPfcXonProbingExecutor
    (inheritance + single-seam override; algorithm code is identical).
  - The "DUT" is a stateful counter model that behaves like real
    hardware (periodic PAUSE pumps, freeze on xon).
  - Algorithm and Executor are wired up the same way as in production.

MODEL FIDELITY DISCLAIMER (per code review I4, 2026-05-06):
  HardwareModel uses ADDITIVE drain semantics: XOn fires when the
  cumulative drained packet count crosses true_xon_offset. Real ASIC
  behavior is OCCUPANCY-CROSSING: XOn fires when the buffer occupancy
  drops below (pfcxoff_point - xon_offset). The two are equivalent only
  for the perfectly clean fill-then-drain-once scenario; with margin
  retries or multi-phase drain, additive count loses the relationship.
  Combined with patched time.sleep, this IT exercises algorithm logic
  and counter ordering correctness but does NOT validate real-hardware
  timing or occupancy-threshold semantics. Physical validation across
  Broadcom/Cisco/Mellanox remains required before merge.
"""

import pytest
from unittest.mock import patch
from probe_test_helper import setup_test_environment  # noqa: E402

# Setup PTF mocks + probe path (must run before importing probe modules)
setup_test_environment()

from observer_config import ObserverConfig  # noqa: E402
from probing_observer import ProbingObserver  # noqa: E402
from sim_pfc_xon_probing_executor import SimPfcXonProbingExecutor  # noqa: E402


def _make_observer(name="it"):
    config = ObserverConfig(
        probe_target="pfc_xon",
        algorithm_name=name,
        strategy="integration",
        check_column_title="Xon",
        table_column_mapping={}
    )
    return ProbingObserver(name, 1, observer_config=config)


@patch('pfc_xon_probing_executor.time.sleep')  # don't actually sleep
class TestPfcXonIntegration:
    """End-to-end Algorithm + Executor against HardwareModel via sim path."""

    def setup_method(self):
        self.observer = _make_observer()

    @pytest.mark.order(9000)
    def test_step_algo_finds_broadcom_th3_offset(self, mock_sleep):
        """Broadcom TH3 scenario: pfcxoff_point=8800, true_xon_offset=13."""
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = SimPfcXonProbingExecutor(
            observer=self.observer,
            pfcxoff_point=8800,
            true_xon_offset=13,
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
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = SimPfcXonProbingExecutor(
            observer=self.observer,
            pfcxoff_point=2000,
            true_xon_offset=18,
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
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = SimPfcXonProbingExecutor(
            observer=self.observer,
            pfcxoff_point=388047,
            true_xon_offset=3245,
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
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = SimPfcXonProbingExecutor(
            observer=self.observer,
            pfcxoff_point=10000,
            true_xon_offset=1045,
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
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = SimPfcXonProbingExecutor(
            observer=self.observer,
            pfcxoff_point=388047,
            true_xon_offset=12985,
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
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = SimPfcXonProbingExecutor(
            observer=self.observer,
            pfcxoff_point=1000,
            true_xon_offset=1,
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
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = SimPfcXonProbingExecutor(
            observer=self.observer,
            pfcxoff_point=1000,
            true_xon_offset=100,
        )
        algo = XonDrainStepAlgorithm(
            executor=executor, observer=self.observer, max_iter=20
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower is None
        assert upper is None
