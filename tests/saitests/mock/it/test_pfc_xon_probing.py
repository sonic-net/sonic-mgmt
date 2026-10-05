"""
Integration tests for PfcXon -- Standard Algorithms + Executor + HardwareModel via sim.

Tests the full algorithm flow using framework-standard ThresholdRangeProbingAlgorithm
(binary search) and ThresholdPointProbingAlgorithm (step-by-step, always_full_cycle=True)
against a realistic in-memory hardware model, exercised through the registered
SimPfcXonProbingExecutor (which inherits the real PfcXonProbingExecutor and overrides
only the SAI counter read seam).

Architecture (after C3+C4 refactor, design v3):
  - Small offsets (< ~50 pkts): Point-only path (always_full_cycle=True)
  - Large offsets (> ~50 pkts): Range narrows [0, xoff_point] -> Point finds exact

Coverage:
- Point-only: Broadcom TH3 (offset=13), TD2 (offset=18), edge offset=1
- Range+Point: Cisco J2C (offset=3245), Mellanox PAC (offset=1045), Cisco Q3D (offset=12985)
- Edge cases: offset=1, Point on pre-narrowed range

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
from threshold_point_probing_algorithm import ThresholdPointProbingAlgorithm  # noqa: E402
from threshold_range_probing_algorithm import ThresholdRangeProbingAlgorithm  # noqa: E402


def _make_observer(name="it", iteration_prefix=1):
    config = ObserverConfig(
        probe_target="pfc_xon",
        algorithm_name=name,
        strategy="integration",
        check_column_title="Xon",
        table_column_mapping={
            "lower_bound": "lower",
            "upper_bound": "upper",
            "candidate_threshold": "value",
            "range_step": None,
        },
    )
    return ProbingObserver(name, iteration_prefix, observer_config=config)


@patch('pfc_xon_probing_executor.time.sleep')
class TestPfcXonPointOnly:
    """Point-only path: ThresholdPointProbingAlgorithm(always_full_cycle=True).

    For small-offset SKUs (Broadcom), Range is skipped. Point steps from
    lower_bound+1 upward until XOn fires. always_full_cycle=True ensures
    every iteration is a fresh fill-then-drain cycle (required by PfcXon
    executor semantics where "value" is an absolute drain quantity).
    """

    def setup_method(self):
        self.observer = _make_observer("point_only", iteration_prefix=23)

    def _run_point(self, pfcxoff_point, true_xon_offset):
        """Create executor + Point algo, run on [0, pfcxoff_point]."""
        executor = SimPfcXonProbingExecutor(
            observer=self.observer,
            pfcxoff_point=pfcxoff_point,
            true_xon_offset=true_xon_offset,
            holder_port=2,
        )
        algo = ThresholdPointProbingAlgorithm(
            executor=executor,
            observer=self.observer,
            verification_attempts=1,
            step_size=1,
            always_full_cycle=True,
        )
        return algo.run(
            src_port=0, dst_port=1,
            lower_bound=0, upper_bound=pfcxoff_point,
            pg=3,
        )

    @pytest.mark.order(9000)
    def test_point_finds_broadcom_th3_offset(self, mock_sleep):
        """Broadcom TH3: pfcxoff_point=8800, true_xon_offset=13."""
        lower, upper, elapsed = self._run_point(8800, 13)
        assert lower == 13
        assert upper == 13

    @pytest.mark.order(9001)
    def test_point_finds_broadcom_td2_offset(self, mock_sleep):
        """Broadcom TD2: pfcxoff_point=2000, true_xon_offset=18."""
        lower, upper, elapsed = self._run_point(2000, 18)
        assert lower == 18
        assert upper == 18

    @pytest.mark.order(9002)
    def test_point_finds_offset_one(self, mock_sleep):
        """Edge: true_xon_offset=1 (minimum possible offset)."""
        lower, upper, elapsed = self._run_point(1000, 1)
        assert lower == 1
        assert upper == 1


@patch('pfc_xon_probing_executor.time.sleep')
class TestPfcXonRangeAndPoint:
    """Range+Point path: Range binary search narrows, then Point finds exact.

    For large-offset SKUs (Cisco, Mellanox), ThresholdRangeProbingAlgorithm
    first narrows the window from [0, xoff_point] to a small range
    (< precise_detection_range_limit=100), then ThresholdPointProbingAlgorithm
    steps through the narrowed range to find the exact offset.
    """

    def setup_method(self):
        self.range_observer = _make_observer("range", iteration_prefix=22)
        self.point_observer = _make_observer("point", iteration_prefix=23)

    def _run_range_then_point(self, pfcxoff_point, true_xon_offset):
        """Range narrows -> Point finds exact. Returns (lower, upper, elapsed)."""
        executor = SimPfcXonProbingExecutor(
            observer=self.range_observer,
            pfcxoff_point=pfcxoff_point,
            true_xon_offset=true_xon_offset,
            holder_port=2,
        )
        # Range phase: binary search to narrow window
        range_algo = ThresholdRangeProbingAlgorithm(
            executor=executor,
            observer=self.range_observer,
            precision_target_ratio=0.05,
            verification_attempts=2,
            enable_precise_detection=True,
            precise_detection_range_limit=100,
        )
        range_lower, range_upper, range_elapsed = range_algo.run(
            src_port=0, dst_port=1,
            lower_bound=0, upper_bound=pfcxoff_point,
            pg=3,
        )
        assert range_lower is not None, "Range phase should converge"
        assert range_upper is not None, "Range phase should converge"
        assert range_lower <= true_xon_offset <= range_upper, (
            f"Range [{range_lower}, {range_upper}] should contain "
            f"true offset {true_xon_offset}"
        )

        # Point phase: step through narrowed range to find exact
        point_algo = ThresholdPointProbingAlgorithm(
            executor=executor,
            observer=self.point_observer,
            verification_attempts=1,
            step_size=1,
            always_full_cycle=True,
        )
        point_lower, point_upper, point_elapsed = point_algo.run(
            src_port=0, dst_port=1,
            lower_bound=range_lower, upper_bound=range_upper,
            pg=3,
        )
        return point_lower, point_upper, range_elapsed + point_elapsed

    @pytest.mark.order(9003)
    def test_range_plus_point_finds_cisco_j2c_offset(self, mock_sleep):
        """Cisco J2C: pfcxoff_point=388047, true_xon_offset=3245."""
        lower, upper, elapsed = self._run_range_then_point(388047, 3245)
        assert lower == 3245
        assert upper == 3245

    @pytest.mark.order(9004)
    def test_range_plus_point_finds_mellanox_pac_offset(self, mock_sleep):
        """Mellanox PAC (SN4600C/SPC3): true_xon_offset=1045."""
        lower, upper, elapsed = self._run_range_then_point(10000, 1045)
        assert lower == 1045
        assert upper == 1045

    @pytest.mark.order(9005)
    def test_range_plus_point_finds_cisco_q3d_largest_offset(self, mock_sleep):
        """Cisco Q3D worst case: true_xon_offset=12985 (largest known)."""
        lower, upper, elapsed = self._run_range_then_point(388047, 12985)
        assert lower == 12985
        assert upper == 12985

    @pytest.mark.order(9006)
    def test_point_on_prenarrow_range(self, mock_sleep):
        """Point on a small pre-narrowed range [100, 200] with offset=150."""
        executor = SimPfcXonProbingExecutor(
            observer=self.point_observer,
            pfcxoff_point=5000,
            true_xon_offset=150,
            holder_port=2,
        )
        algo = ThresholdPointProbingAlgorithm(
            executor=executor,
            observer=self.point_observer,
            verification_attempts=1,
            step_size=1,
            always_full_cycle=True,
        )
        lower, upper, elapsed = algo.run(
            src_port=0, dst_port=1,
            lower_bound=100, upper_bound=200,
            pg=3,
        )
        assert lower == 150
        assert upper == 150
