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

import sys  # noqa: F401
import pytest
from unittest.mock import MagicMock

# sys.path injection is handled by conftest.py (probe_dir prepended);
# no per-file hardcoded path needed.

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

    def check_side(src_port, dst_port_a, dst_port_b, value, attempts, **kw):
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
    def test_failed_check_in_binary_phase_does_not_advance_bounds(self):
        """Per code review I2 fix: when a binary midpoint check returns
        success=False, the algorithm must NOT advance bounds (specifically,
        must NOT set upper=mid). Bounds stay where they were; the same
        midpoint is re-probed on the next iteration. After
        max_consecutive_failures, phase 1 aborts and falls through to
        phase 2 step search over the (uncorrupted) window."""
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = MagicMock()
        executor.pfcxoff_point = 1000

        # Pattern: first check fails (success=False), then normal threshold=500
        call_count = [0]

        def side(src_port, dst_port_a, dst_port_b, value, attempts, **kw):
            call_count[0] += 1
            if call_count[0] == 1:
                return (False, False)
            return (True, value >= 500)
        executor.check.side_effect = side

        algo = XonDrainBinaryAlgorithm(
            executor=executor, observer=self.observer, range_limit=16
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        # Should still find an answer despite first failed check.
        # threshold=500 must be in [lower, upper]; lower<500<=upper.
        assert lower is not None
        assert upper is not None
        assert lower < upper
        assert lower < 500 <= upper, \
            f"true threshold 500 must remain in window; got [{lower}, {upper}]"

    @pytest.mark.order(8914.5)
    def test_binary_failed_check_does_not_exclude_real_threshold(self):
        """Regression for code review I2 (2026-05-06): the original code
        moved upper=mid on success=False, which could permanently exclude
        the true threshold from the search window when the failing midpoint
        was lower than the true threshold.

        Setup: true threshold=700, window starts [0, 1000].
          - First call to check(value=500) returns (False, False) — simulated noise.
          - Subsequent check(value=500) returns (True, False) — 500 < 700, no xon.
          - check(value>=700) returns (True, True).

        Old (buggy) behavior: failing mid=500 -> upper=500. True threshold 700
        permanently outside window. Algorithm returns lower<700, upper<=500.

        New behavior: failing mid=500 -> bounds unchanged. Re-probe 500, get
        (True, False), set lower=500. Subsequent binary iterations narrow
        to [688, 700] or similar; phase 2 step finds exact 700.
        """
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = MagicMock()
        executor.pfcxoff_point = 1000

        # Track number of times we've been called for value=500
        first_500_call_done = [False]

        def side(src_port, dst_port_a, dst_port_b, value, attempts, **kw):
            # First call to value=500 is the noisy one
            if value == 500 and not first_500_call_done[0]:
                first_500_call_done[0] = True
                return (False, False)
            return (True, value >= 700)

        executor.check.side_effect = side

        algo = XonDrainBinaryAlgorithm(
            executor=executor, observer=self.observer,
            range_limit=16, binary_max_iter=20, step_max_iter=50
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        # The real threshold (700) must be discoverable
        assert lower is not None and upper is not None, \
            f"algorithm failed to converge; got ({lower}, {upper})"
        assert lower < 700, \
            f"lower={lower} excluded real threshold 700 (would be old-bug behavior)"
        assert upper >= 700, \
            f"upper={upper} excluded real threshold 700 (would be old-bug behavior)"
        assert upper == 700, \
            f"phase 2 step should land exactly on 700, got upper={upper}"

    @pytest.mark.order(8914.7)
    def test_binary_aborts_after_max_consecutive_failures(self):
        """If executor.check returns success=False repeatedly (>=3 times in
        a row), phase 1 aborts and phase 2 step search runs over the
        uncorrupted window. This ensures pathological always-failing
        executors don't loop forever and don't corrupt bounds."""
        from xon_drain_binary_algorithm import XonDrainBinaryAlgorithm

        executor = MagicMock()
        executor.pfcxoff_point = 100   # small so step phase can cover full window

        # Always fail in binary phase; succeed in step phase (xon fires at d=50)
        # We can't distinguish phases here because executor.check is the same.
        # Strategy: count failures, fail first 3 calls, then return (True, value>=50).
        fail_counter = [0]

        def side(src_port, dst_port_a, dst_port_b, value, attempts, **kw):
            if fail_counter[0] < 3:
                fail_counter[0] += 1
                return (False, False)
            return (True, value >= 50)

        executor.check.side_effect = side

        algo = XonDrainBinaryAlgorithm(
            executor=executor, observer=self.observer,
            range_limit=16, binary_max_iter=20, step_max_iter=100
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        # Phase 1 aborted after 3 failures (bounds untouched at [0, 100]).
        # Phase 2 steps from 1 to 100, finds first xon at d=50.
        assert lower == 49 and upper == 50, \
            f"phase 2 should find threshold=50; got lower={lower}, upper={upper}"

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
