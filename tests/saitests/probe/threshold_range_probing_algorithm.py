"""
Threshold Range Probing Algorithm - Unified Implementation

Generic precision range detection algorithm that works with any probing type
(PFC Xoff, Ingress Drop, etc.) through the ProbingExecutorProtocol interface.

Phase 3 Strategy:
- Start with range from Phase 2 (lower_bound to upper_bound)
- Binary search with adaptive termination (5% precision OR fixed range limit)
- Stack-based backtracking for noise resilience
- Multiple verification attempts for noise-resilient detection

Key principles:
1. Pure algorithm logic - no hardware/platform dependencies
2. Executor-agnostic through protocol interface
3. Binary search with dynamic precision control
4. Stack-based backtracking for verification failures
"""

import sys
from typing import Optional, Tuple

# Import model setup for both production and testing environments
if __package__ in (None, ""):
    import os
    _this_dir = os.path.dirname(os.path.abspath(__file__))
    _saitests_dir = os.path.dirname(_this_dir)
    if _saitests_dir not in sys.path:
        sys.path.insert(0, _saitests_dir)
    __package__ = "probe"

from probing_executor_protocol import ProbingExecutorProtocol
from probing_observer import ProbingObserver
from iteration_outcome import IterationOutcome


class ThresholdRangeProbingAlgorithm:
    """
    Unified Threshold Range Detection Algorithm

    Implements Phase 3: Precision Range Detection using binary search with adaptive
    precision control, providing the final threshold range for detection.

    This algorithm works with ANY executor implementing ProbingExecutorProtocol:
    - PfcxoffProbingExecutor
    - IngressDropProbingExecutor
    - MockExecutors
    - Future executor types

    Strategy:
    - Binary search within [lower_bound, upper_bound]
    - Adaptive termination: range_size <= candidate_threshold * 5% OR fixed range limit
    - Stack-based backtracking for verification failures
    - Noise-resilient verification (configurable attempts)
    """

    def __init__(self, executor: ProbingExecutorProtocol,
                 observer: ProbingObserver,
                 precision_target_ratio: float = 0.05,
                 verification_attempts: int = 5,
                 enable_precise_detection: bool = False,
                 precise_detection_range_limit: int = 100):
        """
        Initialize threshold range probing algorithm

        Args:
            executor: Any executor implementing ProbingExecutorProtocol
            observer: Result tracking and reporting (unified ProbingObserver)
            precision_target_ratio: Dynamic precision target (default 5%)
            verification_attempts: How many times to repeat each check and require consistency
            enable_precise_detection: Enable precise step-by-step detection mode
            precise_detection_range_limit: Range limit for precise detection (default 100)
        """
        self.executor = executor
        self.observer = observer
        self.precision_target_ratio = precision_target_ratio
        self.verification_attempts = verification_attempts
        self.enable_precise_detection = enable_precise_detection
        self.precise_detection_range_limit = precise_detection_range_limit

    def run(self, src_port: int, dst_port: int,
            lower_bound: int, upper_bound: int, **traffic_keys) -> Tuple[Optional[int], Optional[int], float]:
        """
        Run threshold range detection algorithm

        Args:
            src_port: Source port for traffic generation
            dst_port: Destination port for threshold detection
            lower_bound: Lower bound discovered from Phase 2
            upper_bound: Upper bound discovered from Phase 1
            **traffic_keys: Traffic identification keys (e.g., pg=3, queue=5)

        Returns:
            Tuple[lower_bound, upper_bound, phase_time]: Detected threshold range
                with phase time or (None, None, 0.0) on failure
        """
        try:
            # Prepare ports for threshold probing
            self.executor.prepare(src_port, dst_port)

            # Phase 3: Precision Range Detection using binary search with
            # dynamic precision control
            # Initialize range stack for backtracking support
            range_stack = [(lower_bound, upper_bound)]
            next_step = "init"  # Step description for next iteration
            iteration = 0
            max_iterations = 50  # Safety limit
            phase_time = 0.0  # Track cumulative phase time

            while iteration < max_iterations and range_stack:
                iteration += 1
                range_start, range_end = range_stack[-1]
                candidate_threshold = (range_start + range_end) // 2

                # Add search window information for Phase 3 (complete window available)
                self.observer.on_iteration_start(iteration, candidate_threshold, range_start, range_end, next_step)

                # Check dynamic precision target with precise detection optimization
                range_size = range_end - range_start

                # Use different precision control based on mode
                if self.enable_precise_detection:
                    # Precise detection mode: use fixed range limit to minimize step-by-step iterations
                    precision_reached = range_size <= self.precise_detection_range_limit
                else:
                    # Normal mode: use dynamic precision (5% of threshold magnitude)
                    precision_reached = range_size <= candidate_threshold * self.precision_target_ratio

                if precision_reached:
                    # Output a summary row indicating precision already met, no probe needed
                    iteration_time, phase_time = self.observer.on_iteration_complete(
                        iteration, candidate_threshold, IterationOutcome.SKIPPED)
                    return (range_start, range_end, phase_time)

                # Noise-resilient verification with multiple attempts
                success, detected = self.executor.check(
                    src_port, dst_port, candidate_threshold,
                    attempts=self.verification_attempts, iteration=iteration, **traffic_keys
                )

                iteration_time, phase_time = self.observer.on_iteration_complete(
                    iteration, candidate_threshold,
                    IterationOutcome.from_check_result(detected, success)
                )

                if not success:
                    # Verification failed - backtrack to parent range
                    range_stack.pop()
                    next_step = "L<->U"  # Backtrace: expand window
                    # Let while condition handle stack exhaustion check
                else:
                    if detected:
                        # Threshold triggered - search left half
                        new_range = (range_start, candidate_threshold)
                        next_step = "<-U"  # Search left: upper bound shrinking
                    else:
                        # Threshold dismissed - search right half
                        new_range = (candidate_threshold + 1, range_end)
                        next_step = "L->"  # Search right: lower bound rising

                    range_stack.append(new_range)

            # Unified error handling after while loop exit
            if iteration >= max_iterations:
                self.observer.on_error(f"Threshold range detection exceeded maximum iterations ({max_iterations})")
            elif not range_stack:
                # Stack exhausted due to backtracking failures
                self.observer.on_error("Threshold range backtrack exhausted all ranges")
            else:
                # Defensive - should not happen under normal conditions
                self.observer.on_error("Threshold range detection terminated unexpectedly")

            return (None, None, phase_time)

        except Exception as e:
            self.observer.on_error(f"Threshold range detection algorithm execution failed: {e}")
            return (None, None, 0.0)
