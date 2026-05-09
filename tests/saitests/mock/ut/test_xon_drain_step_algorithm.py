"""
Unit tests for XonDrainStepAlgorithm — step-by-step XOn drain probing.

Covers:
- Successful detection at various D values
- Exhaustion (xon never fires within max_iter)
- Verification failures (executor.check returns success=False)
- prepare() being called once at start
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
        algorithm_name="StepTest",
        strategy="step_by_step",
        check_column_title="Xon",
        table_column_mapping={}
    )
    return ProbingObserver("test", 1, observer_config=config)


def _make_executor(pfcxoff_point=1000):
    """Create a mock executor that satisfies the algorithm's protocol.
    Has prepare() and check() methods + pfcxoff_point attribute."""
    ex = MagicMock()
    ex.pfcxoff_point = pfcxoff_point
    return ex


class TestXonDrainStepAlgorithm:
    def setup_method(self):
        self.observer = _make_observer()

    @pytest.mark.order(8900)
    def test_finds_xon_at_d_equals_5(self):
        """xon fires at D=5 -> answer is (4, 5)."""
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = _make_executor()

        # check returns (success, xon_fired). xon fires when D=5.
        def check_side(src_port, dst_port_a, dst_port_b, value, attempts, **kw):
            return (True, value >= 5)
        executor.check.side_effect = check_side

        algo = XonDrainStepAlgorithm(executor=executor, observer=self.observer, max_iter=20)
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 4
        assert upper == 5
        assert elapsed >= 0
        executor.prepare.assert_called_once_with(24, 28, 29)
        # Should have called check exactly 5 times (D=1..5)
        assert executor.check.call_count == 5

    @pytest.mark.order(8901)
    def test_finds_xon_at_d_equals_1(self):
        """xon fires immediately at D=1."""
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = _make_executor()
        executor.check.return_value = (True, True)

        algo = XonDrainStepAlgorithm(executor=executor, observer=self.observer, max_iter=20)
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 0
        assert upper == 1
        assert executor.check.call_count == 1

    @pytest.mark.order(8902)
    def test_exhausts_max_iter_returns_none(self):
        """xon never fires within max_iter -> returns (None, None)."""
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = _make_executor()
        executor.check.return_value = (True, False)  # never fires

        algo = XonDrainStepAlgorithm(executor=executor, observer=self.observer, max_iter=10)
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower is None
        assert upper is None
        assert executor.check.call_count == 10

    @pytest.mark.order(8903)
    def test_failed_check_retries_same_d_then_advances(self):
        """If executor.check returns success=False (inconsistent), retry the
        SAME D up to max_consecutive_failures times. Per I1 fix (2026-05-09):
        advancing on failure causes off-by-one bias when noise hits at the
        true threshold; retry-same-D preserves the search invariant."""
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = _make_executor()
        # D=1: 1 failure then success-not-fired; D=2: success-not-fired;
        # D=3: 2 failures then success-fired (success after retries on same D=3)
        responses = [
            (False, False),  # D=1 attempt 1: fail
            (True, False),   # D=1 attempt 2 (retry SAME D=1): success, not fired
            (True, False),   # D=2: success, not fired
            (False, False),  # D=3 attempt 1: fail
            (False, False),  # D=3 attempt 2 (retry SAME D=3): fail again
            (True, True),    # D=3 attempt 3 (retry SAME D=3): success, fired
        ]
        executor.check.side_effect = responses

        algo = XonDrainStepAlgorithm(
            executor=executor, observer=self.observer, max_iter=20,
            max_consecutive_failures=3,
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        # Answer is (D-1, D) = (2, 3) since D=3 fired (NOT (3, 4) which would
        # be the buggy behavior of advancing on failure -- the bug I1 fixes).
        assert lower == 2
        assert upper == 3
        assert executor.check.call_count == 6

    @pytest.mark.order(8906)
    def test_aborts_when_consecutive_failures_exceed_cap(self):
        """When max_consecutive_failures consecutive check failures hit at
        the SAME D, algorithm aborts and returns (None, None). Mirrors
        XonDrainBinaryAlgorithm's abort-on-repeated-failure pattern."""
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = _make_executor()
        # All checks fail at D=1 -> 3 consecutive failures -> abort
        executor.check.return_value = (False, False)

        algo = XonDrainStepAlgorithm(
            executor=executor, observer=self.observer, max_iter=20,
            max_consecutive_failures=3,
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower is None
        assert upper is None
        # Exactly max_consecutive_failures=3 calls made before abort
        assert executor.check.call_count == 3

    @pytest.mark.order(8907)
    def test_consecutive_failure_counter_resets_on_success(self):
        """If D=k fails once but succeeds on retry, the failure counter must
        reset so D=k+1's first failure doesn't push past the cap due to
        carry-over from D=k. Critical correctness property."""
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = _make_executor()
        # D=1: fail, retry -> success-not-fired (counter reset after success).
        # D=2: fail, retry -> success-not-fired (counter reset).
        # D=3: success-fired.
        # Without counter reset, D=2's first failure would be the 3rd
        # cumulative failure -> incorrect abort.
        responses = [
            (False, False),  # D=1 attempt 1: fail (counter=1)
            (True, False),   # D=1 attempt 2: success not fired (counter reset)
            (False, False),  # D=2 attempt 1: fail (counter=1, NOT 2)
            (True, False),   # D=2 attempt 2: success not fired (counter reset)
            (True, True),    # D=3 attempt 1: success fired
        ]
        executor.check.side_effect = responses

        algo = XonDrainStepAlgorithm(
            executor=executor, observer=self.observer, max_iter=20,
            max_consecutive_failures=3,
        )
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 2
        assert upper == 3
        assert executor.check.call_count == 5

    @pytest.mark.order(8904)
    def test_passes_traffic_keys_to_executor(self):
        """traffic_keys (e.g., pg=3) must be forwarded to executor.check."""
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = _make_executor()
        executor.check.return_value = (True, True)

        algo = XonDrainStepAlgorithm(executor=executor, observer=self.observer, max_iter=5)
        algo.run(24, 28, 29, pg=3, queue=5)

        call_kwargs = executor.check.call_args.kwargs
        assert call_kwargs["pg"] == 3
        assert call_kwargs["queue"] == 5

    @pytest.mark.order(8905)
    def test_verification_attempts_propagated(self):
        """verification_attempts is forwarded to executor.check as `attempts`."""
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = _make_executor()
        executor.check.return_value = (True, True)

        algo = XonDrainStepAlgorithm(
            executor=executor, observer=self.observer,
            verification_attempts=3, max_iter=5
        )
        algo.run(24, 28, 29, pg=3)

        assert executor.check.call_args.kwargs["attempts"] == 3
