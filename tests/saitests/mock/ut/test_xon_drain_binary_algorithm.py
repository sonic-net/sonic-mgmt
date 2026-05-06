"""
Unit tests for XonDrainBinaryAlgorithm — binary-then-step XOn drain probing.

Covers:
- Binary search converges to range_limit window
- Phase 2 step finds exact threshold within window
- Cisco-scale offsets (pfcxoff_point=12000, threshold at 3245)
- Failures: binary doesn't converge, step exhausts window
- prepare() called once
- traffic_keys forwarded
"""

import sys
import pytest
from unittest.mock import MagicMock

sys.path.insert(0, r'c:\ws\repo\sonic-mgmt-int\sonic-mgmt-int\tests\saitests\probe')

from observer_config import ObserverConfig  # noqa: E402
from probing_observer import ProbingObserver  # noqa: E402


def _make_observer():
    config = ObserverConfig(
        probe_target="pfc_xon",
        algorithm_name="BinaryTest",
        strategy="binary_then_step",
        check_column_title="Xon",
        table_column_mapping={}
    )
    return ProbingObserver("test", 1, observer_config=config)


def _make_executor_with_threshold(pfcxoff_point, true_threshold):
    """Create a mock executor where xon fires iff value >= true_threshold."""
    ex = MagicMock()
    ex.pfcxoff_point = pfcxoff_point

    def check_side(src_port, dst_port_a, dst_port_b, value, attempts, iteration, **kw):
        return (True, value >= true_threshold)
    ex.check.side_effect = check_side
    return ex


class TestXonDrainBinaryAlgorithm:
    def setup_method(self):
        self.observer = _make_observer()

    @pytest.mark.order(8910)
    def test_finds_threshold_cisco_scale(self):
        """Cisco J2C scenario: pfcxoff_point=12985, true_threshold=3245.
        Binary should narrow to ≤32 within ~10 iters; step finds 3245."""
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = _make_executor_with_threshold(pfcxoff_point=12985, true_threshold=3245)

        algo = XonDrainBinaryAlgorithm(
            executor=executor, observer=self.observer, range_limit=32
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 3244
        assert upper == 3245
        executor.prepare.assert_called_once_with(24, 28, 29)
        # Total iterations should be much less than 3245 (the naive step count)
        assert executor.check.call_count < 60

    @pytest.mark.order(8911)
    def test_finds_threshold_mellanox_pac_scale(self):
        """Mellanox PAC scenario: pfcxoff_point=2000 (some xoff value),
        true_threshold=1024 (hysteresis-dominated)."""
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = _make_executor_with_threshold(pfcxoff_point=2000, true_threshold=1024)

        algo = XonDrainBinaryAlgorithm(
            executor=executor, observer=self.observer, range_limit=16
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 1023
        assert upper == 1024
        # Binary log2(2000) ≈ 11; step within 16 = ≤27 total
        assert executor.check.call_count < 30

    @pytest.mark.order(8912)
    def test_threshold_exactly_at_pfcxoff_point(self):
        """Edge: threshold equals pfcxoff_point (xon only fires when
        almost everything drained)."""
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = _make_executor_with_threshold(pfcxoff_point=1000, true_threshold=1000)

        algo = XonDrainBinaryAlgorithm(
            executor=executor, observer=self.observer, range_limit=16
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert upper == 1000
        assert lower == 999

    @pytest.mark.order(8913)
    def test_threshold_too_low_for_binary_to_find(self):
        """Edge: threshold=1 (xon fires for any drain). Binary should
        narrow upper toward 1; phase 2 step finds exact."""
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = _make_executor_with_threshold(pfcxoff_point=1000, true_threshold=1)

        algo = XonDrainBinaryAlgorithm(
            executor=executor, observer=self.observer, range_limit=16
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 0
        assert upper == 1

    @pytest.mark.order(8914)
    def test_failed_check_in_binary_phase_treated_as_pessimistic(self):
        """If a binary midpoint check fails (success=False), narrow window
        toward upper (treat ambiguous as 'too aggressive')."""
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = MagicMock()
        executor.pfcxoff_point = 1000

        # Pattern: first check fails (success=False), then normal threshold=500
        call_count = [0]
        def side(src_port, dst_port_a, dst_port_b, value, attempts, iteration, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return (False, False)
            return (True, value >= 500)
        executor.check.side_effect = side

        algo = XonDrainBinaryAlgorithm(
            executor=executor, observer=self.observer, range_limit=16
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        # Should still find an answer despite first failed check
        assert lower is not None
        assert upper is not None
        assert lower < upper

    @pytest.mark.order(8915)
    def test_traffic_keys_forwarded(self):
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = _make_executor_with_threshold(pfcxoff_point=1000, true_threshold=500)

        algo = XonDrainBinaryAlgorithm(
            executor=executor, observer=self.observer, range_limit=32
        )
        algo.run(24, 28, 29, pg=3, queue=5)

        call_kwargs = executor.check.call_args.kwargs
        assert call_kwargs["pg"] == 3
        assert call_kwargs["queue"] == 5

    @pytest.mark.order(8916)
    def test_verification_attempts_propagated(self):
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = _make_executor_with_threshold(pfcxoff_point=1000, true_threshold=500)

        algo = XonDrainBinaryAlgorithm(
            executor=executor, observer=self.observer,
            range_limit=32, verification_attempts=2
        )
        algo.run(24, 28, 29, pg=3)

        assert executor.check.call_args.kwargs["attempts"] == 2

    @pytest.mark.order(8917)
    def test_step_phase_exhaustion_returns_none(self):
        """Pathological: binary converges to a window but step-by-step
        within window also fails (xon never fires in [lower+1, upper])."""
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = MagicMock()
        executor.pfcxoff_point = 1000
        # Binary phase: never fires (return (True, False) for all binary
        # midpoints) -> upper stays at 1000, lower grows.
        # But binary will hit binary_max_iter without converging.
        executor.check.return_value = (True, False)

        algo = XonDrainBinaryAlgorithm(
            executor=executor, observer=self.observer,
            range_limit=16, binary_max_iter=15, step_max_iter=20
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        # Binary never narrowed (xon never fires) -> returns None
        assert lower is None or upper is None
