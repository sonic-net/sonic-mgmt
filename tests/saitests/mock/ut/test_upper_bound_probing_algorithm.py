"""
Unit Tests for UpperBoundProbingAlgorithm

Tests the Phase 1 upper bound discovery algorithm using exponential growth (x2)
until threshold is triggered. Verifies algorithm logic, edge cases, and error handling.

Coverage target: 90%+
"""

import sys
import pytest
from unittest.mock import MagicMock

# Import test utilities
sys.path.insert(0, '../../probe')

from upper_bound_probing_algorithm import UpperBoundProbingAlgorithm  # noqa: E402
from probing_executor_protocol import ProbingExecutorProtocol  # noqa: E402
from probing_observer import ProbingObserver  # noqa: E402


class TestUpperBoundProbingAlgorithm:
    """Test suite for UpperBoundProbingAlgorithm"""

    def setUp(self):
        """Set up clean mocks for each test"""
        self.mock_executor = MagicMock(spec=ProbingExecutorProtocol)
        self.mock_observer = MagicMock(spec=ProbingObserver)
        self.mock_observer.on_iteration_complete.return_value = (0.1, 0.5)  # iteration_time, phase_time

    @pytest.mark.order(8000)
    def test_initialization_default_parameters(self):
        """Test algorithm initialization with default parameters"""
        self.setUp()
        algo = UpperBoundProbingAlgorithm(self.mock_executor, self.mock_observer)

        assert algo.executor == self.mock_executor
        assert algo.observer == self.mock_observer
        assert algo.verification_attempts == 1

    @pytest.mark.order(8010)
    def test_initialization_custom_verification_attempts(self):
        """Test algorithm initialization with custom verification attempts"""
        self.setUp()
        algo = UpperBoundProbingAlgorithm(
            self.mock_executor, self.mock_observer, verification_attempts=3
        )

        assert algo.verification_attempts == 3

    @pytest.mark.order(8020)
    def test_run_immediate_threshold_trigger(self):
        """Test when threshold triggers on first iteration"""
        self.setUp()
        self.mock_executor.check.return_value = (True, True)  # success, detected

        algo = UpperBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, initial_value=1000, pg=3)

        # Verify result
        assert result == 1000
        assert phase_time == 0.5

        # Verify executor calls
        self.mock_executor.prepare.assert_called_once_with(24, 28)
        self.mock_executor.check.assert_called_once_with(
            24, 28, 1000, attempts=1, iteration=1, pg=3
        )

        # Verify observer calls
        self.mock_observer.on_iteration_start.assert_called_once()
        self.mock_observer.on_iteration_complete.assert_called_once()

    @pytest.mark.order(8030)
    def test_run_exponential_growth_until_trigger(self):
        """Test exponential growth (x2) until threshold triggers"""
        self.setUp()
        # First 3 iterations: no trigger, 4th iteration: trigger
        self.mock_executor.check.side_effect = [
            (True, False),  # 100: dismissed
            (True, False),  # 200: dismissed
            (True, False),  # 400: dismissed
            (True, True),   # 800: triggered
        ]

        algo = UpperBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, initial_value=100)

        # Verify result
        assert result == 800

        # Verify executor check calls with exponential growth
        assert self.mock_executor.check.call_count == 4
        calls = self.mock_executor.check.call_args_list
        assert calls[0][0][2] == 100   # current value
        assert calls[1][0][2] == 200   # current * 2
        assert calls[2][0][2] == 400   # current * 2
        assert calls[3][0][2] == 800   # current * 2

    @pytest.mark.order(8040)
    def test_run_verification_failure(self):
        """Test when verification fails during search"""
        self.setUp()
        # First iteration succeeds, second fails
        self.mock_executor.check.side_effect = [
            (True, False),   # 100: dismissed
            (False, False),  # 200: verification failed
        ]

        algo = UpperBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, initial_value=100)

        # Verify failure result
        assert result is None

        # Verify error was logged
        self.mock_observer.on_error.assert_called_once()
        assert "verification failed" in self.mock_observer.on_error.call_args[0][0].lower()

    @pytest.mark.order(8050)
    def test_run_maximum_iterations_exceeded(self):
        """Test safety limit when max iterations exceeded"""
        self.setUp()
        # Always return dismissed (never trigger)
        self.mock_executor.check.return_value = (True, False)

        algo = UpperBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, initial_value=1)

        # Verify failure result
        assert result is None

        # Verify error was logged
        self.mock_observer.on_error.assert_called_once()
        assert "exceeded maximum iterations" in self.mock_observer.on_error.call_args[0][0].lower()

    @pytest.mark.order(8060)
    def test_run_with_traffic_keys(self):
        """Test that traffic keys are passed through correctly"""
        self.setUp()
        self.mock_executor.check.return_value = (True, True)

        algo = UpperBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(
            src_port=24, dst_port=28, initial_value=500, pg=3, queue=5
        )

        # Verify traffic keys passed to executor
        self.mock_executor.check.assert_called_once_with(
            24, 28, 500, attempts=1, iteration=1, pg=3, queue=5
        )

    @pytest.mark.order(8070)
    def test_run_observer_iteration_tracking(self):
        """Test that observer correctly tracks iterations"""
        self.setUp()
        self.mock_executor.check.side_effect = [
            (True, False),  # Iteration 1
            (True, False),  # Iteration 2
            (True, True),   # Iteration 3
        ]

        algo = UpperBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, initial_value=100)

        # Verify observer iteration start calls
        assert self.mock_observer.on_iteration_start.call_count == 3
        start_calls = self.mock_observer.on_iteration_start.call_args_list

        # Check iteration numbers and values
        assert start_calls[0][0] == (1, 100, None, None, "init")
        assert start_calls[1][0] == (2, 200, None, None, "x2")
        assert start_calls[2][0] == (3, 400, None, None, "x2")

        # Verify observer iteration complete calls
        assert self.mock_observer.on_iteration_complete.call_count == 3

    @pytest.mark.order(8080)
    def test_run_exception_handling(self):
        """Test exception handling during algorithm execution"""
        self.setUp()
        self.mock_executor.prepare.side_effect = RuntimeError("Hardware failure")

        algo = UpperBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, initial_value=100)

        # Verify failure result
        assert result is None
        assert phase_time == 0.0

        # Verify error was logged
        self.mock_observer.on_error.assert_called_once()
        assert "algorithm execution failed" in self.mock_observer.on_error.call_args[0][0].lower()

    @pytest.mark.order(8090)
    def test_run_phase_time_accumulation(self):
        """Test that phase time accumulates correctly"""
        self.setUp()
        # Mock observer returns different times for each iteration
        self.mock_observer.on_iteration_complete.side_effect = [
            (0.1, 0.1),  # iteration_time, cumulative_phase_time
            (0.2, 0.3),
            (0.15, 0.45),
        ]
        self.mock_executor.check.side_effect = [
            (True, False),
            (True, False),
            (True, True),
        ]

        algo = UpperBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, initial_value=100)

        # Verify final phase time matches last cumulative value
        assert phase_time == 0.45

    @pytest.mark.order(8100)
    def test_run_custom_verification_attempts(self):
        """Test that custom verification attempts are used"""
        self.setUp()
        self.mock_executor.check.return_value = (True, True)

        algo = UpperBoundProbingAlgorithm(
            self.mock_executor, self.mock_observer, verification_attempts=5
        )
        result, phase_time = algo.run(src_port=24, dst_port=28, initial_value=100)

        # Verify executor called with custom attempts
        self.mock_executor.check.assert_called_once_with(
            24, 28, 100, attempts=5, iteration=1
        )

    @pytest.mark.order(8110)
    def test_run_iteration_outcome_reporting(self):
        """Test that correct iteration outcomes are reported"""
        self.setUp()
        from iteration_outcome import IterationOutcome

        self.mock_executor.check.side_effect = [
            (True, False),  # Should report DISMISSED
            (True, True),   # Should report TRIGGERED
        ]

        algo = UpperBoundProbingAlgorithm(self.mock_executor, self.mock_observer)
        result, phase_time = algo.run(src_port=24, dst_port=28, initial_value=100)

        # Verify iteration complete calls with correct outcomes
        complete_calls = self.mock_observer.on_iteration_complete.call_args_list
        assert complete_calls[0][0][2].value == IterationOutcome.UNREACHED.value
        assert complete_calls[1][0][2].value == IterationOutcome.REACHED.value


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
