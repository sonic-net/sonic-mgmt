#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for ThresholdResult dataclass.

Tests cover:
- Factory methods (from_bounds, failed)
- Properties (is_point, is_range, value, candidate)
- Point vs Range differentiation
- Success and failure states
- __repr__ string representation

Coverage target: 100% for probing_result.py
"""

import pytest
import unittest


# Import the class under test
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../probe"))
from probing_result import ThresholdResult  # noqa: E402


@pytest.mark.order(5200)
class TestThresholdResultFactoryMethods(unittest.TestCase):
    """Test ThresholdResult factory methods."""

    @pytest.mark.order(5200)
    def test_from_bounds_success(self):
        """Test from_bounds creates successful result with both bounds."""
        result = ThresholdResult.from_bounds(100, 200)

        assert result.lower_bound == 100
        assert result.upper_bound == 200
        assert result.success is True

    @pytest.mark.order(5210)
    def test_from_bounds_failure_both_none(self):
        """Test from_bounds creates failed result when both bounds are None."""
        result = ThresholdResult.from_bounds(None, None)

        assert result.lower_bound is None
        assert result.upper_bound is None
        assert result.success is False

    @pytest.mark.order(5220)
    def test_from_bounds_failure_lower_none(self):
        """Test from_bounds creates failed result when lower is None."""
        result = ThresholdResult.from_bounds(None, 200)

        assert result.lower_bound is None
        assert result.upper_bound == 200
        assert result.success is False

    @pytest.mark.order(5230)
    def test_from_bounds_failure_upper_none(self):
        """Test from_bounds creates failed result when upper is None."""
        result = ThresholdResult.from_bounds(100, None)

        assert result.lower_bound == 100
        assert result.upper_bound is None
        assert result.success is False

    @pytest.mark.order(5240)
    def test_failed_factory_method(self):
        """Test failed() creates failed result."""
        result = ThresholdResult.failed()

        assert result.lower_bound is None
        assert result.upper_bound is None
        assert result.success is False
        assert result.phase_time == 0.0


@pytest.mark.order(5250)
class TestThresholdResultPointVsRange(unittest.TestCase):
    """Test point vs range differentiation."""

    @pytest.mark.order(5250)
    def test_is_point_when_bounds_equal(self):
        """Test is_point returns True when lower == upper."""
        result = ThresholdResult.from_bounds(150, 150)

        assert result.is_point is True
        assert result.is_range is False

    @pytest.mark.order(5260)
    def test_is_range_when_bounds_different(self):
        """Test is_range returns True when lower < upper."""
        result = ThresholdResult.from_bounds(100, 200)

        assert result.is_point is False
        assert result.is_range is True

    @pytest.mark.order(5270)
    def test_is_point_false_on_failure(self):
        """Test is_point returns False for failed result."""
        result = ThresholdResult.failed()

        assert result.is_point is False

    @pytest.mark.order(5280)
    def test_is_range_false_on_failure(self):
        """Test is_range returns False for failed result."""
        result = ThresholdResult.failed()

        assert result.is_range is False

    @pytest.mark.order(5290)
    def test_point_with_zero_value(self):
        """Test point detection with zero value."""
        result = ThresholdResult.from_bounds(0, 0)

        assert result.is_point is True
        assert result.lower_bound == 0
        assert result.upper_bound == 0


@pytest.mark.order(5300)
class TestThresholdResultValueProperty(unittest.TestCase):
    """Test value property."""

    @pytest.mark.order(5300)
    def test_value_returns_lower_bound_for_point(self):
        """Test value property returns lower_bound for point result."""
        result = ThresholdResult.from_bounds(150, 150)

        assert result.value == 150

    @pytest.mark.order(5310)
    def test_value_returns_lower_bound_for_range(self):
        """Test value property returns lower_bound for range result."""
        result = ThresholdResult.from_bounds(100, 200)

        assert result.value == 100

    @pytest.mark.order(5320)
    def test_value_returns_none_for_failure(self):
        """Test value property returns None for failed result."""
        result = ThresholdResult.failed()

        assert result.value is None


@pytest.mark.order(5330)
class TestThresholdResultCandidateProperty(unittest.TestCase):
    """Test candidate property."""

    @pytest.mark.order(5330)
    def test_candidate_returns_value_for_point(self):
        """Test candidate returns exact value for point result."""
        result = ThresholdResult.from_bounds(150, 150)

        assert result.candidate == 150

    @pytest.mark.order(5340)
    def test_candidate_returns_midpoint_for_range(self):
        """Test candidate returns midpoint for range result."""
        result = ThresholdResult.from_bounds(100, 200)

        # Midpoint: (100 + 200) // 2 = 150
        assert result.candidate == 150

    @pytest.mark.order(5350)
    def test_candidate_midpoint_with_odd_range(self):
        """Test candidate midpoint calculation with odd range."""
        result = ThresholdResult.from_bounds(100, 201)

        # Midpoint: (100 + 201) // 2 = 150 (integer division)
        assert result.candidate == 150

    @pytest.mark.order(5360)
    def test_candidate_returns_none_for_failure(self):
        """Test candidate returns None for failed result."""
        result = ThresholdResult.failed()

        assert result.candidate is None


@pytest.mark.order(5370)
class TestThresholdResultPhaseTime(unittest.TestCase):
    """Test phase_time attribute."""

    @pytest.mark.order(5370)
    def test_phase_time_default_value(self):
        """Test phase_time defaults to 0.0."""
        result = ThresholdResult.from_bounds(100, 200)

        assert result.phase_time == 0.0

    @pytest.mark.order(5380)
    def test_phase_time_custom_value(self):
        """Test phase_time can be set to custom value."""
        result = ThresholdResult(
            lower_bound=100,
            upper_bound=200,
            success=True,
            phase_time=123.45
        )

        assert result.phase_time == 123.45

    @pytest.mark.order(5390)
    def test_phase_time_persists_in_from_bounds(self):
        """Test phase_time is 0.0 in from_bounds (factory doesn't set it)."""
        result = ThresholdResult.from_bounds(100, 200)

        # from_bounds doesn't set phase_time, so it defaults to 0.0
        assert result.phase_time == 0.0


@pytest.mark.order(5400)
class TestThresholdResultRepresentation(unittest.TestCase):
    """Test __repr__ string representation."""

    @pytest.mark.order(5400)
    def test_repr_for_failed_result(self):
        """Test __repr__ for failed result."""
        result = ThresholdResult.failed()

        repr_str = repr(result)
        assert repr_str == "ThresholdResult(FAILED)"

    @pytest.mark.order(5410)
    def test_repr_for_point_result(self):
        """Test __repr__ for point result."""
        result = ThresholdResult.from_bounds(150, 150)

        repr_str = repr(result)
        assert repr_str == "ThresholdResult(point=150)"

    @pytest.mark.order(5420)
    def test_repr_for_range_result(self):
        """Test __repr__ for range result."""
        result = ThresholdResult.from_bounds(100, 200)

        repr_str = repr(result)
        assert repr_str == "ThresholdResult(range=[100, 200])"

    @pytest.mark.order(5430)
    def test_repr_for_zero_point(self):
        """Test __repr__ for point at zero."""
        result = ThresholdResult.from_bounds(0, 0)

        repr_str = repr(result)
        assert repr_str == "ThresholdResult(point=0)"


@pytest.mark.order(5440)
class TestThresholdResultDirectInstantiation(unittest.TestCase):
    """Test direct instantiation of ThresholdResult."""

    @pytest.mark.order(5440)
    def test_direct_instantiation_success(self):
        """Test creating ThresholdResult directly with success=True."""
        result = ThresholdResult(
            lower_bound=100,
            upper_bound=200,
            success=True
        )

        assert result.lower_bound == 100
        assert result.upper_bound == 200
        assert result.success is True
        assert result.is_range is True

    @pytest.mark.order(5450)
    def test_direct_instantiation_failure(self):
        """Test creating ThresholdResult directly with success=False."""
        result = ThresholdResult(
            lower_bound=None,
            upper_bound=None,
            success=False
        )

        assert result.lower_bound is None
        assert result.upper_bound is None
        assert result.success is False

    @pytest.mark.order(5460)
    def test_direct_instantiation_with_all_fields(self):
        """Test creating ThresholdResult with all fields."""
        result = ThresholdResult(
            lower_bound=100,
            upper_bound=100,
            success=True,
            phase_time=45.67
        )

        assert result.lower_bound == 100
        assert result.upper_bound == 100
        assert result.success is True
        assert result.phase_time == 45.67
        assert result.is_point is True


@pytest.mark.order(5470)
class TestThresholdResultEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    @pytest.mark.order(5470)
    def test_large_values(self):
        """Test with large threshold values."""
        result = ThresholdResult.from_bounds(1000000, 2000000)

        assert result.lower_bound == 1000000
        assert result.upper_bound == 2000000
        assert result.candidate == 1500000

    @pytest.mark.order(5480)
    def test_adjacent_values(self):
        """Test with adjacent lower and upper bounds."""
        result = ThresholdResult.from_bounds(100, 101)

        assert result.is_range is True
        assert result.candidate == 100  # (100 + 101) // 2 = 100

    @pytest.mark.order(5490)
    def test_same_value_point(self):
        """Test point result with specific same value."""
        result = ThresholdResult.from_bounds(999, 999)

        assert result.is_point is True
        assert result.value == 999
        assert result.candidate == 999


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
