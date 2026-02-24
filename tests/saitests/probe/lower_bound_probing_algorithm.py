"""
Lower Bound Probing Algorithm - Unified Implementation

Generic lower bound detection algorithm that works with any probing type
(PFC Xoff, Ingress Drop, etc.) through the ProbingExecutorProtocol interface.

Phase 2 Strategy:
- Start from upper_bound/2 as initial value
- Logarithmically reduce (/2) until threshold dismissed
- Single verification attempt for speed optimization
- Leverages upper bound result from Phase 1

Key principles:
1. Pure algorithm logic - no hardware/platform dependencies
2. Executor-agnostic through protocol interface
3. Logarithmic reduction for rapid convergence
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


class LowerBoundProbingAlgorithm:
    """
    Unified Lower Bound Detection Algorithm

    Implements Phase 2: Lower Bound Detection using logarithmic reduction (/2)
    until threshold is dismissed, providing the lower boundary for subsequent phases.

    This algorithm works with ANY executor implementing ProbingExecutorProtocol:
    - PfcxoffProbingExecutor
    - IngressDropProbingExecutor
    - MockExecutors
    - Future executor types

    Strategy:
    - Start from upper_bound/2
    - Logarithmically reduce (/2) until threshold dismissed
    - Single verification for speed
    - Safety limit to prevent infinite loops
    """

    def __init__(self, executor: ProbingExecutorProtocol, observer: ProbingObserver,
                 verification_attempts: int = 1):
        """
        Initialize lower bound probing algorithm

        Args:
            executor: Any executor implementing ProbingExecutorProtocol
            observer: Result tracking and reporting (unified ProbingObserver)
            verification_attempts: How many times to repeat the same check and require consistency
        """
        self.executor = executor
        self.observer = observer
        self.verification_attempts = verification_attempts

    def run(self, src_port: int, dst_port: int, upper_bound: int,
            start_value: int = None, **traffic_keys) -> Tuple[Optional[int], float]:
        """
        Run lower bound detection algorithm

        Args:
            src_port: Source port for traffic generation
            dst_port: Destination port for threshold detection
            upper_bound: Upper bound discovered from Phase 1
            start_value: Optional starting value for lower bound search (optimization).
                        If provided, skip the normal upper_bound/2 calculation and start from this value.
            **traffic_keys: Traffic identification keys (e.g., pg=3, queue=5)
                        Useful when we know a value that definitely won't trigger the threshold.
                        For example, for Ingress Drop, use (pfc_xoff_threshold - 1) since Drop >= XOFF.

        Returns:
            Tuple[Optional[int], float]: (lower_bound, phase_time) or (None, 0.0) on failure
        """
        try:
            # Prepare ports for threshold probing
            self.executor.prepare(src_port, dst_port)

            # Phase 2: Lower Bound Detection using logarithmic reduction (/2)
            # OPTIMIZATION: Use start_value if provided, otherwise default to upper_bound/2
            if start_value is not None:
                current = start_value
            else:
                current = upper_bound // 2
            iteration = 0
            max_iterations = 20  # Safety limit
            phase_time = 0.0  # Track cumulative phase time

            while iteration < max_iterations and current >= 1:
                iteration += 1

                # Add search window information for Phase 2 (no lower bound yet, only upper)
                self.observer.on_iteration_start(
                    iteration, current, None, upper_bound,
                    "init" if iteration == 1 else "/2"
                )

                # Phase 2: use a single verification attempt for speed
                success, detected = self.executor.check(
                    src_port, dst_port, current, attempts=self.verification_attempts,
                    iteration=iteration, **traffic_keys
                )

                iteration_time, phase_time = self.observer.on_iteration_complete(
                    iteration, current, IterationOutcome.from_check_result(detected, success)
                )

                if not success:
                    self.observer.on_error(f"Lower bound verification failed at iteration {iteration}")
                    return (None, phase_time)

                if not detected:
                    # Threshold dismissed - lower bound found
                    return (current, phase_time)
                else:
                    # Continue logarithmic reduction
                    current = max(current // 2, 1)

            self.observer.on_error(
                "Lower bound detection exceeded maximum iterations or reached minimum value")
            return (None, phase_time)

        except Exception as e:
            self.observer.on_error(f"Lower bound detection algorithm execution failed: {e}")
            return (None, 0.0)
