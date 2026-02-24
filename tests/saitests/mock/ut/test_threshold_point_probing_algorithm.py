"""
Unit Tests for ThresholdPointProbingAlgorithm

Tests the Phase 4 precise threshold point detection algorithm using step-by-step
increment with incremental packet sending optimization. Verifies algorithm logic,
edge cases, and error handling.

Coverage target: 90%+
"""

import sys
import pytest
import unittest
from unittest.mock import MagicMock

# Import test utilities
sys.path.insert(0, '../../probe')

from threshold_point_probing_algorithm import ThresholdPointProbingAlgorithm  # noqa: E402
from probing_executor_protocol import ProbingExecutorProtocol  # noqa: E402
from probing_observer import ProbingObserver  # noqa: E402


class TestThresholdPointProbingAlgorithm:
    """Test suite for ThresholdPointProbingAlgorithm"""

    def setUp(self):
        """Set up clean mocks for each test"""
        self.mock_executor = MagicMock(spec=ProbingExecutorProtocol)
        self.mock_observer = MagicMock(spec=ProbingObserver)
        self.mock_observer.on_iteration_complete.return_value = (0.1, 0.5)

    @pytest.mark.order(8400)
    def test_initialization_default_parameters(self):
        """Test algorithm initialization with default parameters"""
        self.setUp()
        algo = ThresholdPointProbingAlgorithm(self.mock_executor, self.mock_observer)

        assert algo.executor == self.mock_executor
        assert algo.observer == self.mock_observer
        assert algo.verification_attempts == 1
        assert algo.step_size == 1

    @pytest.mark.order(8410)
    def test_initialization_custom_parameters(self):
        """Test algorithm initialization with custom parameters"""
        self.setUp()
        algo = ThresholdPointProbingAlgorithm(
            self.mock_executor, self.mock_observer,
            verification_attempts=3, step_size=2
        )

        assert algo.verification_attempts == 3
        assert algo.step_size == 2

    @pytest.mark.order(8420)
    def test_run_immediate_threshold_trigger(self):
        """Test when threshold triggers on first iteration (lower_bound+1)"""
        self.setUp()
        self.mock_executor.check.return_value = (True, True)  # success, detected

        algo = ThresholdPointProbingAlgorithm(self.mock_executor, self.mock_observer)
        lower, upper, phase_time = algo.run(
            src_port=24, dst_port=28, lower_bound=100, upper_bound=200, pg=3
        )

        # Verify result (threshold at lower_bound+1 = 101)
        assert lower == 101
        assert upper == 101
        assert phase_time == 0.5

        # Verify executor calls
        self.mock_executor.prepare.assert_called_once_with(24, 28)
        # First iteration: drain_buffer=True, send full value
        self.mock_executor.check.assert_called_once_with(
            24, 28, value=101, attempts=1, drain_buffer=True, iteration=1, pg=3
        )

    @pytest.mark.order(8430)
    def test_run_step_by_step_until_trigger(self):
        """Test step-by-step increment until threshold triggers"""
        self.setUp()
        # Dismissed for 101-104, triggered at 105
        self.mock_executor.check.side_effect = [
            (True, False),  # 101: dismissed
            (True, False),  # 102: dismissed
            (True, False),  # 103: dismissed
            (True, False),  # 104: dismissed
            (True, True),   # 105: triggered
        ]

        algo = ThresholdPointProbingAlgorithm(self.mock_executor, self.mock_observer)
        lower, upper, phase_time = algo.run(
            src_port=24, dst_port=28, lower_bound=100, upper_bound=110
        )

        # Verify result
        assert lower == 105
        assert upper == 105

        # Verify executor check calls
        assert self.mock_executor.check.call_count == 5
        calls = self.mock_executor.check.call_args_list

        # First iteration: full value, drain buffer
        assert calls[0][1]['value'] == 101
        assert calls[0][1]['drain_buffer'] is True
        assert calls[0][1]['attempts'] == 1

        # Subsequent iterations: incremental value (step_size=1), no drain
        for i in range(1, 5):
            assert calls[i][1]['value'] == 1  # step_size
            assert calls[i][1]['drain_buffer'] is False
            assert calls[i][1]['attempts'] == 1

    @pytest.mark.order(8440)
    def test_run_with_custom_step_size(self):
        """Test using custom step_size for faster probing"""
        self.setUp()
        # step_size=2: range(101, 111, 2) = 101, 103, 105, 107, 109
        self.mock_executor.check.side_effect = [
            (True, False),  # 101: dismissed
            (True, False),  # 103: dismissed
            (True, True),   # 105: triggered
        ]

        algo = ThresholdPointProbingAlgorithm(
            self.mock_executor, self.mock_observer, step_size=2
        )
        lower, upper, phase_time = algo.run(
            src_port=24, dst_port=28, lower_bound=100, upper_bound=110
        )

        # Verify result (step_size=2: 101, 103, 105)
        assert lower == 105
        assert upper == 105

        # Verify step-by-step progression with step_size=2
        calls = self.mock_executor.check.call_args_list
        # First iteration: full value = 101, drain buffer
        assert calls[0][1]['value'] == 101
        assert calls[0][1]['drain_buffer'] is True
        # Subsequent iterations: incremental send with step_size=2
        assert calls[1][1]['value'] == 2
        assert calls[1][1]['drain_buffer'] is False
        assert calls[2][1]['value'] == 2
        assert calls[2][1]['drain_buffer'] is False

    @pytest.mark.order(8450)
    def test_run_no_threshold_found_in_range(self):
        """Test when no threshold found in entire range"""
        self.setUp()
        # Always dismissed (never trigger)
        self.mock_executor.check.return_value = (True, False)

        algo = ThresholdPointProbingAlgorithm(self.mock_executor, self.mock_observer)
        lower, upper, phase_time = algo.run(
            src_port=24, dst_port=28, lower_bound=100, upper_bound=105
        )

        # Verify failure result
        assert lower is None
        assert upper is None
        assert phase_time > 0  # Should still have accumulated time

        # Verify all values in range were checked (101-105)
        assert self.mock_executor.check.call_count == 5

    @pytest.mark.order(8460)
    def test_run_verification_failure_continues(self):
        """Test that verification failures are handled gracefully"""
        self.setUp()
        # First iteration fails, but algorithm continues
        self.mock_executor.check.side_effect = [
            (False, False),  # 101: verification failed (continue)
            (True, False),   # 102: dismissed
            (True, True),    # 103: triggered
        ]

        algo = ThresholdPointProbingAlgorithm(self.mock_executor, self.mock_observer)
        lower, upper, phase_time = algo.run(
            src_port=24, dst_port=28, lower_bound=100, upper_bound=110
        )

        # Verify result (continues despite failure)
        assert lower == 103
        assert upper == 103

    @pytest.mark.order(8470)
    def test_run_with_traffic_keys(self):
        """Test that traffic keys are passed through correctly"""
        self.setUp()
        self.mock_executor.check.return_value = (True, True)

        algo = ThresholdPointProbingAlgorithm(self.mock_executor, self.mock_observer)
        lower, upper, phase_time = algo.run(
            src_port=24, dst_port=28, lower_bound=100, upper_bound=110,
            pg=3, queue=5
        )

        # Verify traffic keys passed to executor
        self.mock_executor.check.assert_called_once()
        assert self.mock_executor.check.call_args[1]['pg'] == 3
        assert self.mock_executor.check.call_args[1]['queue'] == 5

    @pytest.mark.order(8480)
    def test_run_observer_iteration_tracking(self):
        """Test that observer correctly tracks iterations"""
        self.setUp()
        self.mock_executor.check.side_effect = [
            (True, False),  # Iteration 1
            (True, False),  # Iteration 2
            (True, True),   # Iteration 3
        ]

        algo = ThresholdPointProbingAlgorithm(self.mock_executor, self.mock_observer)
        lower, upper, phase_time = algo.run(
            src_port=24, dst_port=28, lower_bound=100, upper_bound=110
        )

        # Verify observer iteration start calls
        assert self.mock_observer.on_iteration_start.call_count == 3
        start_calls = self.mock_observer.on_iteration_start.call_args_list

        # Check iteration numbers and search window
        assert start_calls[0][0] == (1, 101, 101, 110, "init")
        assert start_calls[1][0] == (2, 102, 102, 110, "+1")
        assert start_calls[2][0] == (3, 103, 103, 110, "+1")

    @pytest.mark.order(8490)
    def test_run_exception_handling(self):
        """Test exception handling during algorithm execution"""
        self.setUp()
        self.mock_executor.prepare.side_effect = RuntimeError("Hardware failure")

        algo = ThresholdPointProbingAlgorithm(self.mock_executor, self.mock_observer)
        lower, upper, phase_time = algo.run(
            src_port=24, dst_port=28, lower_bound=100, upper_bound=110
        )

        # Verify failure result
        assert lower is None
        assert upper is None
        assert phase_time == 0.0

        # Verify error was logged
        self.mock_observer.on_error.assert_called_once()
        assert "threshold point detection error" in self.mock_observer.on_error.call_args[0][0].lower()

    @pytest.mark.order(8500)
    def test_run_phase_time_accumulation(self):
        """Test that phase time accumulates correctly"""
        self.setUp()
        self.mock_observer.on_iteration_complete.side_effect = [
            (0.1, 0.1),
            (0.2, 0.3),
            (0.15, 0.45),
        ]
        self.mock_executor.check.side_effect = [
            (True, False),
            (True, False),
            (True, True),
        ]

        algo = ThresholdPointProbingAlgorithm(self.mock_executor, self.mock_observer)
        lower, upper, phase_time = algo.run(
            src_port=24, dst_port=28, lower_bound=100, upper_bound=110
        )

        # Verify final phase time
        assert phase_time == 0.45

    @pytest.mark.order(8510)
    def test_run_first_iteration_uses_verification_attempts(self):
        """Test that first iteration uses configured verification_attempts"""
        self.setUp()
        self.mock_executor.check.return_value = (True, True)

        algo = ThresholdPointProbingAlgorithm(
            self.mock_executor, self.mock_observer, verification_attempts=5
        )
        lower, upper, phase_time = algo.run(
            src_port=24, dst_port=28, lower_bound=100, upper_bound=110
        )

        # Verify first iteration used custom verification_attempts
        self.mock_executor.check.assert_called_once()
        assert self.mock_executor.check.call_args[1]['attempts'] == 5

    @pytest.mark.order(8520)
    def test_run_iteration_outcome_reporting(self):
        """Test that correct iteration outcomes are reported"""
        self.setUp()
        from iteration_outcome import IterationOutcome

        self.mock_executor.check.side_effect = [
            (True, False),  # Should report DISMISSED
            (True, True),   # Should report TRIGGERED
        ]

        algo = ThresholdPointProbingAlgorithm(self.mock_executor, self.mock_observer)
        lower, upper, phase_time = algo.run(
            src_port=24, dst_port=28, lower_bound=100, upper_bound=110
        )

        # Verify iteration complete calls with correct outcomes
        complete_calls = self.mock_observer.on_iteration_complete.call_args_list
        assert complete_calls[0][0][2].value == IterationOutcome.UNREACHED.value
        assert complete_calls[1][0][2].value == IterationOutcome.REACHED.value

    @pytest.mark.order(8530)
    def test_run_custom_step_size_in_observer_messages(self):
        """Test that custom step_size is reflected in observer messages"""
        self.setUp()
        self.mock_executor.check.side_effect = [
            (True, False),
            (True, True),
        ]

        algo = ThresholdPointProbingAlgorithm(
            self.mock_executor, self.mock_observer, step_size=4
        )
        lower, upper, phase_time = algo.run(
            src_port=24, dst_port=28, lower_bound=100, upper_bound=120
        )

        # Verify observer messages show correct step size
        # range(101, 121, 4) = 101, 105, 109, 113, 117
        start_calls = self.mock_observer.on_iteration_start.call_args_list
        assert start_calls[0][0][1] == 101  # lower_bound + 1
        assert start_calls[1][0][1] == 105  # 101 + 4


@pytest.mark.order(8540)
class TestThresholdPointProbingFixedRangeConvergence(unittest.TestCase):
    """
    Test Point Probing with fixed range convergence guarantee.

    Design Doc Reference: §3.4.5, §5.3
    Key Design Point: Fixed range convergence bounds Point Probing iterations
    - Threshold Range Probing converges to ~100-200 cells max
    - Point Probing receives this bounded input, limiting iterations
    - Critical for Headroom Pool probing performance
    """

    def setUp(self):
        """Set up test fixtures with proper mock configuration."""
        self.mock_executor = MagicMock()
        self.mock_observer = MagicMock()
        # Observer must return (iteration_time, cumulative_time) from on_iteration_complete
        self.mock_observer.on_iteration_complete.return_value = (0.1, 0.1)

    @pytest.mark.order(8540)
    def test_point_probing_with_converged_range_100_cells(self):
        """Test Point Probing with 100-cell converged range (typical from Range Probing)."""
        # Simulate Range Probing output: converged to 100-cell range
        # Threshold is at 20050
        # Algorithm starts at lower_bound+1 = 20001, ends at 20050 (50 iterations)
        self.mock_executor.check.side_effect = \
            [(True, False)] * 49 + [(True, True)]  # 49 unreached + 1 threshold at 20050

        algo = ThresholdPointProbingAlgorithm(
            self.mock_executor, self.mock_observer, step_size=1
        )

        point, _, _ = algo.run(
            src_port=24, dst_port=28,
            lower_bound=20000, upper_bound=20100  # 100-cell range
        )

        # Verify:
        # 1. Point found within range
        assert 20000 <= point <= 20100, "Point must be within input range"
        # 2. Bounded iterations (at most 100 for 100-cell range)
        assert self.mock_executor.check.call_count <= 100, \
            "Point Probing iterations bounded by input range size"
        # 3. Found exact point
        assert point == 20050

    @pytest.mark.order(8550)
    def test_point_probing_with_converged_range_150_cells(self):
        """Test Point Probing with 150-cell converged range."""
        # Threshold at position 75 (middle of 150-cell range)
        self.mock_executor.check.side_effect = (
            [(True, False)] * 74 +  # 1-74: not reached
            [(True, True)]          # 75: reached
        )

        algo = ThresholdPointProbingAlgorithm(
            self.mock_executor, self.mock_observer, step_size=1
        )

        point, _, _ = algo.run(
            src_port=24, dst_port=28,
            lower_bound=1000, upper_bound=1150  # 150-cell range
        )

        assert point == 1075
        assert self.mock_executor.check.call_count == 75, \
            "Should find threshold in 75 iterations (middle of range)"
        assert self.mock_executor.check.call_count <= 150, \
            "Point Probing bounded by 150-cell input range"

    @pytest.mark.order(8560)
    def test_point_probing_performance_guarantee(self):
        """Test that Point Probing time is bounded by converged range size."""
        # Worst case: threshold at end of range
        range_size = 200  # Max expected from Range Probing convergence
        self.mock_executor.check.side_effect = (
            [(True, False)] * (range_size - 1) +  # All fail except last
            [(True, True)]  # Last one hits threshold
        )

        algo = ThresholdPointProbingAlgorithm(
            self.mock_executor, self.mock_observer, step_size=1
        )

        point, _, _ = algo.run(
            src_port=24, dst_port=28,
            lower_bound=5000, upper_bound=5000 + range_size
        )

        # Verify performance guarantee: max iterations = range_size
        assert self.mock_executor.check.call_count == range_size, \
            f"Worst case: {range_size} iterations for {range_size}-cell range"
        assert point == 5200  # 5000 + 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
