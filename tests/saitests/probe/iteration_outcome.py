"""
Iteration Outcome Enum - Unified Result Type for Probing Iterations

This module defines the IterationOutcome enum that represents the complete
outcome of a single probing iteration, replacing the previous (detected, success)
two-parameter approach with a single, semantically clear enum value.

Design Rationale:
- Simplifies API: one parameter instead of two boolean-like parameters
- Type-safe: Enum prevents invalid combinations
- Self-documenting: Each value clearly describes what happened
- Matches output: Values correspond directly to markdown table 'Check' column

Note on SKIPPED:
- SKIPPED is NOT a result from executor.check() - it indicates the algorithm
  decided not to call check() because the precision target was already met.
- This is a valid iteration outcome that should be reported to the observer.
- It's included here because IterationOutcome represents "what happened in this
  iteration", not just "what did check() return".
"""

from enum import Enum


class IterationOutcome(Enum):
    """
    Outcome of a single probing iteration

    This enum represents the complete outcome of an iteration, including:
    1. Cases where executor.check() was called and returned a result
    2. Cases where check was intentionally skipped by the algorithm

    Values directly correspond to the 'Check' column in markdown table output.

    Mapping from old API:
        REACHED   ← detected=True,  success=True
        UNREACHED ← detected=False, success=True
        FAILED    ← detected=any,   success=False
        SKIPPED   ← detected=None,  success=True  (new: check not executed)
    """

    # executor.check() called -> threshold was triggered
    REACHED = "reached"

    # executor.check() called -> threshold was NOT triggered
    UNREACHED = "unreached"

    # executor.check() called -> verification failed (inconsistent results)
    FAILED = "failed"

    # executor.check() NOT called -> precision already satisfied, no probe needed
    SKIPPED = "skipped"

    @classmethod
    def from_check_result(cls, detected: bool, success: bool) -> "IterationOutcome":
        """
        Convert legacy (detected, success) parameters to IterationOutcome

        This helper method supports gradual migration from the old API.

        Args:
            detected: True if threshold was triggered, False if not
            success: True if verification completed without errors

        Returns:
            Corresponding IterationOutcome value
        """
        if not success:
            return cls.FAILED
        return cls.REACHED if detected else cls.UNREACHED
