"""
Threshold Point Probing Algorithm - Unified Implementation

Generic precise threshold point detection algorithm that works with any probing type
(PFC Xoff, Ingress Drop, etc.) through the ProbingExecutorProtocol interface.

This module implements precise threshold detection through step-by-step
packet increment within a known threshold range. Unlike the three-phase discovery
algorithm which finds a range, this algorithm finds the exact threshold point.

Design principles:
1. Pure algorithm logic - no hardware/platform dependencies
2. Executor-agnostic through protocol interface
3. Step-by-step increment from lower_bound to upper_bound
4. Stops at first threshold trigger point
5. Performance optimization - incremental packet sending strategy
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


class ThresholdPointProbingAlgorithm:
    """
    Unified Precise Threshold Point Detection Algorithm

    Implements precise threshold point detection through:
    1. Step-by-step increment from lower_bound to upper_bound
    2. 1-packet increment per iteration
    3. Stops at first threshold trigger
    4. Performance optimized packet sending

    This algorithm works with ANY executor implementing ProbingExecutorProtocol:
    - PfcxoffProbingExecutor
    - IngressDropProbingExecutor
    - MockExecutors
    - Future executor types

    Key features:
    - Precise point detection (not range)
    - Single verification per step (configurable)
    - Optimized packet sending strategy
    - Failure detection if no threshold found in range
    """

    def __init__(self, executor: ProbingExecutorProtocol, observer: ProbingObserver,
                 verification_attempts: int = 1,
                 step_size: int = 1):
        """
        Initialize threshold point probing algorithm

        Args:
            executor: Any executor implementing ProbingExecutorProtocol
            observer: Unified ProbingObserver for Phase 4 (threshold_point)
            verification_attempts: How many times to repeat each check and require consistency
            step_size: Step increment size (default 1, can be 2, 4, etc. for faster probing)
        """
        self.executor = executor
        self.observer = observer
        self.verification_attempts = verification_attempts
        self.step_size = step_size

    def run(self, src_port: int, dst_port: int, lower_bound: int,
            upper_bound: int, **traffic_keys) -> Tuple[Optional[int], Optional[int], float]:
        """
        Probe for precise threshold point within known range

        Args:
            src_port: Source port for sending traffic
            dst_port: Destination port for threshold detection
            lower_bound: Starting point for step-by-step search
            upper_bound: End point for search range
            **traffic_keys: Traffic identification keys (e.g., pg=3, queue=5)
            upper_bound: Maximum search limit

        Returns:
            Tuple[lower_bound, upper_bound, phase_time] where:
                (point, point, time): precise threshold found with phase execution time
                (None, None, 0.0):    not found or error
        """
        try:
            # Step 1: Prepare ports for precise detection
            self.executor.prepare(src_port, dst_port)

            # Step 2: Step-by-step search from lower_bound to upper_bound
            # Use incremental packet sending for performance optimization
            # Start from lower_bound+1 since lower_bound is confirmed unreached (skip known value)
            step = self.step_size
            phase_time = 0.0  # Track cumulative phase time

            for iteration, current_packets in enumerate(range(lower_bound + 1, upper_bound + 1, step), start=1):
                # Dynamic control variables based on iteration
                if current_packets == lower_bound + 1:
                    # First iteration: drain buffer and send total packets
                    send_value = current_packets
                    drain_buffer = True
                    attempts = self.verification_attempts  # Allow retries on first check
                else:
                    # Subsequent iterations: incremental sending without buffer draining
                    send_value = step
                    drain_buffer = False
                    attempts = 1  # No retries for incremental mode (unidirectional growth)

                # Pass current_packets as lower bound (current testing point) and
                # upper_bound as window for markdown table display
                # This ensures the bounds column shows the current search range
                # [current_value, upper_bound]
                self.observer.on_iteration_start(
                    iteration, current_packets, current_packets, upper_bound,
                    "init" if iteration == 1 else f"+{step}"
                )

                # Check if current packet count triggers threshold
                success, detected = self.executor.check(
                    src_port, dst_port,
                    value=send_value,
                    attempts=attempts,
                    drain_buffer=drain_buffer,
                    iteration=iteration,
                    **traffic_keys
                )

                iteration_time, phase_time = self.observer.on_iteration_complete(
                    iteration, current_packets, IterationOutcome.from_check_result(detected, success)
                )

                if not success:
                    # Verification failed - this shouldn't happen with attempts=1 but handle gracefully
                    continue

                if detected:
                    # Found precise threshold point!
                    precise_threshold = current_packets
                    return (precise_threshold, precise_threshold, phase_time)

            # Step 3: No threshold found in range - algorithm failure
            return (None, None, phase_time)

        except Exception as e:
            self.observer.on_error(f"Threshold point detection error: {e}")
            return (None, None, 0.0)
