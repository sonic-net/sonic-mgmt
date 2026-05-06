"""
Unit tests for XonDrainStepAlgorithm — step-by-step XOn drain probing.

Covers:
- Successful detection at various D values
- Exhaustion (xon never fires within max_iter)
- Verification failures (executor.check returns success=False)
- prepare() being called once at start
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
        def check_side(src_port, dst_port_a, dst_port_b, value, attempts, iteration, **kw):
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
    def test_failed_check_continues_to_next_d(self):
        """If executor.check returns success=False (inconsistent), skip
        and continue trying next D."""
        from xon_drain_step_algorithm import XonDrainStepAlgorithm

        executor = _make_executor()
        # D=1: failed, D=2: not fired, D=3: failed, D=4: fired
        responses = [(False, False), (True, False), (False, False), (True, True)]
        executor.check.side_effect = responses

        algo = XonDrainStepAlgorithm(executor=executor, observer=self.observer, max_iter=20)
        lower, upper, elapsed = algo.run(24, 28, 29, pg=3)

        assert lower == 3
        assert upper == 4
        assert executor.check.call_count == 4

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
