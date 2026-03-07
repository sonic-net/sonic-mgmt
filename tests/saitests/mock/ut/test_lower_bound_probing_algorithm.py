"""
Unit Tests for LowerBoundProbingAlgorithm

Tests the Phase 2 lower bound detection algorithm using logarithmic reduction (/2)
until threshold is dismissed. Verifies algorithm logic, edge cases, and error handling.

Coverage target: 90%+
"""

import sys
import pytest
from unittest.mock import MagicMock

# Import test utilities
sys.path.insert(0, '../../probe')

from lower_bound_probing_algorithm import LowerBoundProbingAlgorithm  # noqa: E402
from probing_executor_protocol import ProbingExecutorProtocol  # noqa: E402
from probing_observer import ProbingObserver  # noqa: E402


class TestLowerBoundProbingAlgorithm:
    """Test suite for LowerBoundProbingAlgorithm"""

    def setUp(self):
        """Set up clean mocks for each test"""
        self.mock_executor = MagicMock(spec=ProbingExecutorProtocol)
        self.mock_observer = MagicMock(spec=ProbingObserver)
        self.mock_observer.on_iteration_complete.return_value = (0.1, 0.5)  # iteration_time, phase_time

    @pytest.mark.order(8200)
    def test_initialization_default_parameters(self):
        """Test algorithm initialization with default parameters"""
        self.setUp()
        algo = LowerBoundProbingAlgorithm(self.mock_executor, self.mock_observer)

        assert algo.executor == self.mock_executor
        assert algo.observer == self.mock_observer
        assert algo.verification_attempts == 1

    @pytest.mark.order(8210)
    def test_initialization_custom_verification_attempts(self):
        """Test algorithm initialization with custom verification attempts"""
        self.setUp()
        algo = LowerBoundProbingAlgorithm(
            self.mock_executor, self.mock_observer, verification_attempts=3
        )

        assert algo.verification_attempts == 3

    @pytest.mark.order(8220)
    def test_run_immediate_threshold_dismiss(self):
        """Test when threshold dismissed on first iteration"""
        self.setUp()
        self.mock_executor.check.return_value = (True, False)  # success, dismissed

        algo = LowerBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, upper_bound=1000, pg=3)

        # Verify result (default start is upper_bound/2 = 500)
        assert result == 500
        assert phase_time == 0.5

        # Verify executor calls
        self.mock_executor.prepare.assert_called_once_with(24, 28)
        self.mock_executor.check.assert_called_once_with(
            24, 28, 500, attempts=1, iteration=1, pg=3
        )

    @pytest.mark.order(8230)
    def test_run_logarithmic_reduction_until_dismiss(self):
        """Test logarithmic reduction (/2) until threshold dismissed"""
        self.setUp()
        # First 3 iterations: triggered, 4th iteration: dismissed
        self.mock_executor.check.side_effect = [
            (True, True),   # 500: triggered
            (True, True),   # 250: triggered
            (True, True),   # 125: triggered
            (True, False),  # 62: dismissed
        ]

        algo = LowerBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, upper_bound=1000)

        # Verify result
        assert result == 62

        # Verify executor check calls with logarithmic reduction
        assert self.mock_executor.check.call_count == 4
        calls = self.mock_executor.check.call_args_list
        assert calls[0][0][2] == 500   # 1000 / 2
        assert calls[1][0][2] == 250   # 500 / 2
        assert calls[2][0][2] == 125   # 250 / 2
        assert calls[3][0][2] == 62    # 125 / 2

    @pytest.mark.order(8240)
    def test_run_with_custom_start_value(self):
        """Test using custom start_value instead of upper_bound/2"""
        self.setUp()
        self.mock_executor.check.return_value = (True, False)

        algo = LowerBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(
            src_port=24, dst_port=28, upper_bound=1000, start_value=300
        )

        # Verify started from custom value
        assert result == 300
        self.mock_executor.check.assert_called_once_with(
            24, 28, 300, attempts=1, iteration=1
        )

    @pytest.mark.order(8250)
    def test_run_verification_failure(self):
        """Test when verification fails during search"""
        self.setUp()
        # First iteration succeeds, second fails
        self.mock_executor.check.side_effect = [
            (True, True),    # 500: triggered
            (False, False),  # 250: verification failed
        ]

        algo = LowerBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, upper_bound=1000)

        # Verify failure result
        assert result is None

        # Verify error was logged
        self.mock_observer.on_error.assert_called_once()
        assert "verification failed" in self.mock_observer.on_error.call_args[0][0].lower()

    @pytest.mark.order(8260)
    def test_run_maximum_iterations_exceeded(self):
        """Test safety limit when max iterations exceeded"""
        self.setUp()
        # Always return triggered (never dismiss)
        self.mock_executor.check.return_value = (True, True)

        algo = LowerBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, upper_bound=1000000)

        # Verify failure result
        assert result is None

        # Verify error was logged
        self.mock_observer.on_error.assert_called_once()
        assert "exceeded maximum iterations" in self.mock_observer.on_error.call_args[0][0].lower()

    @pytest.mark.order(8270)
    def test_run_reaches_minimum_value(self):
        """Test when reduction reaches minimum value of 1"""
        self.setUp()
        # Always trigger until we reach 1
        self.mock_executor.check.side_effect = [
            (True, True),  # 4: triggered
            (True, True),  # 2: triggered
            (True, True),  # 1: triggered (minimum)
        ]

        algo = LowerBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, upper_bound=8)

        # Verify failure result
        assert result is None

        # Verify error was logged
        self.mock_observer.on_error.assert_called_once()

    @pytest.mark.order(8280)
    def test_run_with_traffic_keys(self):
        """Test that traffic keys are passed through correctly"""
        self.setUp()
        self.mock_executor.check.return_value = (True, False)

        algo = LowerBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(
            src_port=24, dst_port=28, upper_bound=1000, pg=3, queue=5
        )

        # Verify traffic keys passed to executor
        self.mock_executor.check.assert_called_once_with(
            24, 28, 500, attempts=1, iteration=1, pg=3, queue=5
        )

    @pytest.mark.order(8290)
    def test_run_observer_iteration_tracking(self):
        """Test that observer correctly tracks iterations"""
        self.setUp()
        self.mock_executor.check.side_effect = [
            (True, True),   # Iteration 1
            (True, True),   # Iteration 2
            (True, False),  # Iteration 3
        ]

        algo = LowerBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, upper_bound=1000)

        # Verify observer iteration start calls
        assert self.mock_observer.on_iteration_start.call_count == 3
        start_calls = self.mock_observer.on_iteration_start.call_args_list

        # Check iteration numbers and search window
        assert start_calls[0][0] == (1, 500, None, 1000, "init")
        assert start_calls[1][0] == (2, 250, None, 1000, "/2")
        assert start_calls[2][0] == (3, 125, None, 1000, "/2")

    @pytest.mark.order(8300)
    def test_run_exception_handling(self):
        """Test exception handling during algorithm execution"""
        self.setUp()
        self.mock_executor.prepare.side_effect = RuntimeError("Hardware failure")

        algo = LowerBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, upper_bound=1000)

        # Verify failure result
        assert result is None
        assert phase_time == 0.0

        # Verify error was logged
        self.mock_observer.on_error.assert_called_once()
        assert "algorithm execution failed" in self.mock_observer.on_error.call_args[0][0].lower()

    @pytest.mark.order(8310)
    def test_run_phase_time_accumulation(self):
        """Test that phase time accumulates correctly"""
        self.setUp()
        self.mock_observer.on_iteration_complete.side_effect = [
            (0.1, 0.1),
            (0.2, 0.3),
            (0.15, 0.45),
        ]
        self.mock_executor.check.side_effect = [
            (True, True),
            (True, True),
            (True, False),
        ]

        algo = LowerBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, upper_bound=1000)

        # Verify final phase time
        assert phase_time == 0.45

    @pytest.mark.order(8320)
    def test_run_custom_verification_attempts(self):
        """Test that custom verification attempts are used"""
        self.setUp()
        self.mock_executor.check.return_value = (True, False)

        algo = LowerBoundProbingAlgorithm(
            self.mock_executor, self.mock_observer, verification_attempts=5
        )
        result, phase_time = algo.run(src_port=24, dst_port=28, upper_bound=1000)

        # Verify executor called with custom attempts
        self.mock_executor.check.assert_called_once_with(
            24, 28, 500, attempts=5, iteration=1
        )

    @pytest.mark.order(8330)
    def test_run_iteration_outcome_reporting(self):
        """Test that correct iteration outcomes are reported"""
        self.setUp()
        from iteration_outcome import IterationOutcome

        self.mock_executor.check.side_effect = [
            (True, True),   # Should report TRIGGERED
            (True, False),  # Should report DISMISSED
        ]

        algo = LowerBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, upper_bound=1000)

        # Verify iteration complete calls with correct outcomes
        complete_calls = self.mock_observer.on_iteration_complete.call_args_list
        assert complete_calls[0][0][2].value == IterationOutcome.REACHED.value
        assert complete_calls[1][0][2].value == IterationOutcome.UNREACHED.value


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
