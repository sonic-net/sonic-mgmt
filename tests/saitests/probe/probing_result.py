"""
Probing Result Data Class

Defines standardized return type for all probing test cases.
Using dataclass to ensure consistent structure and type safety.

Design principles:
1. Unified format: All probing tests return ThresholdResult
2. Type safety: Dataclass enforces field types
3. Range/Point unification: Point is special case of Range (lower == upper)
4. Nullable: Use Optional for failure cases

Usage:
- PfcXoffProbing: Returns ThresholdResult with PFC XOFF threshold
- IngressDropProbing: Returns ThresholdResult with Ingress Drop threshold
- HeadroomPoolProbing: Returns ThresholdResult with total pool size
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ThresholdResult:
    """
    Unified threshold detection result for all probing types.

    Used by:
    - PfcXoffProbing: threshold = PFC XOFF threshold
    - IngressDropProbing: threshold = Ingress Drop threshold
    - HeadroomPoolProbing: threshold = total headroom pool size

    Attributes:
        lower_bound: Lower bound of threshold range (or exact point if lower == upper)
        upper_bound: Upper bound of threshold range (or exact point if lower == upper)
        success: Whether detection succeeded
        phase_time: Time spent in this phase (seconds), set by algorithm from observer

    Notes:
        - For range: lower_bound < upper_bound
        - For point: lower_bound == upper_bound (precise detection)
        - For failure: lower_bound = upper_bound = None, success = False
    """
    lower_bound: Optional[int]
    upper_bound: Optional[int]
    success: bool
    phase_time: float = 0.0  # Time in seconds for this phase

    @classmethod
    def from_bounds(cls, lower: Optional[int], upper: Optional[int]) -> 'ThresholdResult':
        """Create ThresholdResult from lower/upper bounds."""
        success = lower is not None and upper is not None
        return cls(lower_bound=lower, upper_bound=upper, success=success)

    @classmethod
    def failed(cls) -> 'ThresholdResult':
        """Create a failed result."""
        return cls(lower_bound=None, upper_bound=None, success=False)

    @property
    def is_point(self) -> bool:
        """Check if result is a precise point (lower == upper)."""
        return self.success and self.lower_bound == self.upper_bound

    @property
    def is_range(self) -> bool:
        """Check if result is a range (lower < upper)."""
        return self.success and self.lower_bound < self.upper_bound

    @property
    def value(self) -> Optional[int]:
        """Get threshold value (for point) or lower bound (for range)."""
        return self.lower_bound

    @property
    def candidate(self) -> Optional[int]:
        """Get candidate threshold (midpoint for range, exact value for point)."""
        if not self.success:
            return None
        if self.is_point:
            return self.lower_bound
        # For range: return midpoint
        return (self.lower_bound + self.upper_bound) // 2

    def __repr__(self) -> str:
        if not self.success:
            return "ThresholdResult(FAILED)"
        elif self.is_point:
            return f"ThresholdResult(point={self.lower_bound})"
        else:
            return f"ThresholdResult(range=[{self.lower_bound}, {self.upper_bound}])"
