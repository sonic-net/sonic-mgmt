"""
Upper Bound Probing Algorithm - Unified Implementation

Generic upper bound discovery algorithm that works with any probing type
(PFC Xoff, Ingress Drop, etc.) through the ProbingExecutorProtocol interface.

Phase 1 Strategy:
- Start from buffer_pool_size as initial value
- Exponentially increase (x2) until threshold triggered
- Typically reaches threshold in one iteration since initial value uses buffer pool size
- Single verification attempt for speed optimization

Key principles:
1. Pure algorithm logic - no hardware/platform dependencies
2. Executor-agnostic through protocol interface
3. Exponential growth for rapid convergence
4. Algorithm/Executor/Observer separation for clean testing
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


class UpperBoundProbingAlgorithm:
    """
    Unified Upper Bound Discovery Algorithm

    Implements Phase 1: Upper Bound Discovery using exponential growth (x2)
    until threshold is triggered, providing the upper boundary for subsequent phases.

    This algorithm works with ANY executor implementing ProbingExecutorProtocol:
    - PfcxoffProbingExecutor
    - IngressDropProbingExecutor
    - MockExecutors
    - Future executor types

    Strategy:
    - Start from buffer_pool_size
    - Exponentially increase (x2) until threshold triggered
    - Single verification for speed
    - Safety limit to prevent infinite loops
    """

    def __init__(self, executor: ProbingExecutorProtocol, observer: ProbingObserver,
                 verification_attempts: int = 1):
        """
        Initialize upper bound probing algorithm

        Args:
            executor: Any executor implementing ProbingExecutorProtocol
            observer: Result tracking and reporting (unified ProbingObserver)
            verification_attempts: How many times to repeat the same check and require consistency
        """
        self.executor = executor
        self.observer = observer
        self.verification_attempts = verification_attempts

    def run(self, src_port: int, dst_port: int, initial_value: int, **traffic_keys) -> Tuple[Optional[int], float]:
        """
        Run upper bound discovery algorithm

        Args:
            src_port: Source port for traffic generation
            dst_port: Destination port for threshold detection
            initial_value: Starting value (typically buffer_pool_size)
            **traffic_keys: Traffic identification keys (e.g., pg=3, queue=5)

        Returns:
            Tuple[Optional[int], float]: (upper_bound, phase_time) or (None, 0.0) on failure
        """
        try:
            # Prepare ports for threshold probing
            self.executor.prepare(src_port, dst_port)

            # Phase 1: Upper Bound Discovery using exponential growth (x2)
            current = initial_value
            iteration = 0
            max_iterations = 20  # Safety limit
            phase_time = 0.0  # Track cumulative phase time

            while iteration < max_iterations:
                iteration += 1

                # Add search window information for Phase 1 (no upper bound yet)
                self.observer.on_iteration_start(
                    iteration, current, None, None,
                    "init" if iteration == 1 else "x2"
                )

                # Phase 1: use a single verification attempt for speed
                success, detected = self.executor.check(
                    src_port, dst_port, current, attempts=self.verification_attempts,
                    iteration=iteration, **traffic_keys
                )

                iteration_time, phase_time = self.observer.on_iteration_complete(
                    iteration, current, IterationOutcome.from_check_result(detected, success)
                )

                if not success:
                    self.observer.on_error(f"Upper bound verification failed at iteration {iteration}")
                    return (None, phase_time)

                if detected:
                    # Threshold triggered - upper bound found
                    return (current, phase_time)
                else:
                    # Continue exponential growth
                    current *= 2

            self.observer.on_error(f"Upper bound discovery exceeded maximum iterations ({max_iterations})")
            return (None, phase_time)

        except Exception as e:
            self.observer.on_error(f"Upper bound discovery algorithm execution failed: {e}")
            return (None, 0.0)
