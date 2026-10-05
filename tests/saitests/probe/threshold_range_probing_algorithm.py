"""
Threshold Range Probing Algorithm - Unified Implementation

Generic precision range detection algorithm that works with any probing type
(PFC Xoff, Ingress Drop, etc.) through the ProbingExecutorProtocol interface.

Phase 3 Strategy:
- Start with range from Phase 2 (lower_bound to upper_bound)
- Binary search with adaptive termination (5% precision OR fixed range limit)
- Stack-based backtracking with anti-oscillation nudge for noise resilience
- Multiple verification attempts for noise-resilient detection

Anti-Oscillation Backtrack Design:
    When a child range fails verification, we pop back to its parent range.
    Without adjustment, the parent would produce the same midpoint and same
    child — causing infinite oscillation. To avoid this, we nudge the parent
    range boundary in the direction that makes the failing move less aggressive.

    The nudge direction depends on whether the parent's last successful check
    was 'reached' (threshold triggered → searched left) or 'unreached'
    (threshold not triggered → searched right):

    Scenario 1: Parent unreached → searched right → child FAIL
        Parent's right-move was too aggressive. Nudge parent_start left
        (decrease) so the new midpoint is lower, producing a less aggressive
        right-move next time.
        Adjustment: parent_start -= nudge

    Scenario 2: Parent reached → searched left → child FAIL
        Parent's left-move was too aggressive. Nudge parent_end right
        (increase) so the new midpoint is higher, producing a less aggressive
        left-move next time.
        Adjustment: parent_end += nudge

    Multi-layer backtrack (new parent also fails → pop to grandparent):
        Before applying the nudge to grandparent, merge boundaries to preserve
        the wider search space explored by the failed descendant:
        grandparent = (min(gp_start, failed_start), max(gp_end, failed_end))
        Then apply the same nudge logic based on grandparent's direction.

    Nudge size: proportional to parent range — max(1, range_size // 10).

    6 scenario walkthrough: see unit tests in test_threshold_range_probing_algorithm.py

Key principles:
1. Pure algorithm logic - no hardware/platform dependencies
2. Executor-agnostic through protocol interface
3. Binary search with dynamic precision control
4. Stack-based backtracking with anti-oscillation for verification failures
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
    - Stack-based backtracking with anti-oscillation nudge
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

    @staticmethod
    def _backtrack_nudge(range_start, range_end):
        """Calculate nudge size for anti-oscillation backtrack.

        Proportional to current range: large ranges get larger nudges to
        shift the midpoint meaningfully, small ranges get minimal nudges.

        Returns:
            int: nudge size (at least 1, proportional to range_size // 10)
        """
        return max(1, (range_end - range_start) // 10)

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
            # dynamic precision control and anti-oscillation backtracking
            #
            # Stack entries: (range_start, range_end, direction)
            #   direction: how this range was produced by its parent
            #     'init'    - initial range (no parent)
            #     'right'   - parent was unreached → searched right
            #     'left'    - parent was reached → searched left
            #     'nudge'   - backtracked with anti-oscillation nudge
            STEP_LABELS = {'init': 'init', 'right': 'L->', 'left': '<-U', 'nudge': 'L<->U'}

            range_stack = [(lower_bound, upper_bound, 'init')]
            iteration = 0
            max_iterations = 50
            phase_time = 0.0

            while iteration < max_iterations and range_stack:
                iteration += 1
                range_start, range_end, direction = range_stack[-1]
                candidate_threshold = (range_start + range_end) // 2

                self.observer.on_iteration_start(
                    iteration, candidate_threshold, range_start, range_end,
                    STEP_LABELS.get(direction, direction))

                # Check dynamic precision target
                range_size = range_end - range_start
                if self.enable_precise_detection:
                    precision_reached = range_size <= self.precise_detection_range_limit
                else:
                    precision_reached = range_size <= max(1, int(candidate_threshold * self.precision_target_ratio))

                if precision_reached:
                    iteration_time, phase_time = self.observer.on_iteration_complete(
                        iteration, candidate_threshold, IterationOutcome.SKIPPED)
                    return (range_start, range_end, phase_time)

                # Noise-resilient verification
                success, detected = self.executor.check(
                    src_port, dst_port, candidate_threshold,
                    attempts=self.verification_attempts, iteration=iteration, **traffic_keys
                )

                iteration_time, phase_time = self.observer.on_iteration_complete(
                    iteration, candidate_threshold,
                    IterationOutcome.from_check_result(detected, success)
                )

                if not success:
                    # Backtrack with anti-oscillation nudge:
                    # Pop failed child, nudge parent boundary to shift its
                    # midpoint, preventing the same child from being produced.
                    failed_start, failed_end, _ = range_stack.pop()

                    if range_stack:
                        parent_start, parent_end, parent_dir = range_stack[-1]
                        nudge = self._backtrack_nudge(parent_start, parent_end)

                        # Merge: preserve the wider search space from failed child
                        merged_start = min(parent_start, failed_start)
                        merged_end = max(parent_end, failed_end)

                        # Nudge in the direction opposite to parent's last move
                        if parent_dir in ('right', 'init'):
                            merged_start = max(0, merged_start - nudge)  # Soften right-move
                        else:
                            merged_end += nudge    # Soften left-move

                        range_stack[-1] = (merged_start, merged_end, 'nudge')
                else:
                    if detected:
                        range_stack.append((range_start, candidate_threshold, 'left'))
                    else:
                        range_stack.append((candidate_threshold + 1, range_end, 'right'))

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
