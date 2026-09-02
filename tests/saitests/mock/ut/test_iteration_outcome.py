"""
Unit tests for IterationOutcome enum.

Tests the IterationOutcome enum that represents the complete outcome of a single
probing iteration, including enum values, conversion from legacy API, and string
representation.
"""

import pytest
import sys
from unittest.mock import MagicMock

# Mock PTF and SAI dependencies before importing
sys.modules['ptf'] = MagicMock()
sys.modules['ptf.testutils'] = MagicMock()

# Import the module under test
from iteration_outcome import IterationOutcome  # noqa: E402


# ============================================================================
# Test Class 1: Enum Values (orders 2000-2030)
# ============================================================================

class TestIterationOutcomeEnumValues:
    """Test IterationOutcome enum value definitions."""

    @pytest.mark.order(2000)
    def test_enum_has_four_values(self):
        """Test that IterationOutcome has exactly 4 values."""
        print("\n=== Test: IterationOutcome has 4 values ===")

        values = list(IterationOutcome)

        assert len(values) == 4, f"Expected 4 values, got {len(values)}"
        print(f"[OK] IterationOutcome has 4 values: {[v.name for v in values]}")

    @pytest.mark.order(2010)
    def test_reached_value(self):
        """Test REACHED enum value."""
        print("\n=== Test: REACHED enum value ===")

        assert IterationOutcome.REACHED.value == "reached", \
            f"Expected 'reached', got '{IterationOutcome.REACHED.value}'"
        assert IterationOutcome.REACHED.name == "REACHED", \
            f"Expected 'REACHED', got '{IterationOutcome.REACHED.name}'"
        print("[OK] REACHED value is 'reached'")

    @pytest.mark.order(2020)
    def test_unreached_value(self):
        """Test UNREACHED enum value."""
        print("\n=== Test: UNREACHED enum value ===")

        assert IterationOutcome.UNREACHED.value == "unreached", \
            f"Expected 'unreached', got '{IterationOutcome.UNREACHED.value}'"
        assert IterationOutcome.UNREACHED.name == "UNREACHED", \
            f"Expected 'UNREACHED', got '{IterationOutcome.UNREACHED.name}'"
        print("[OK] UNREACHED value is 'unreached'")

    @pytest.mark.order(2030)
    def test_failed_value(self):
        """Test FAILED enum value."""
        print("\n=== Test: FAILED enum value ===")

        assert IterationOutcome.FAILED.value == "failed", \
            f"Expected 'failed', got '{IterationOutcome.FAILED.value}'"
        assert IterationOutcome.FAILED.name == "FAILED", \
            f"Expected 'FAILED', got '{IterationOutcome.FAILED.name}'"
        print("[OK] FAILED value is 'failed'")

    @pytest.mark.order(2040)
    def test_skipped_value(self):
        """Test SKIPPED enum value."""
        print("\n=== Test: SKIPPED enum value ===")

        assert IterationOutcome.SKIPPED.value == "skipped", \
            f"Expected 'skipped', got '{IterationOutcome.SKIPPED.value}'"
        assert IterationOutcome.SKIPPED.name == "SKIPPED", \
            f"Expected 'SKIPPED', got '{IterationOutcome.SKIPPED.name}'"
        print("[OK] SKIPPED value is 'skipped'")


# ============================================================================
# Test Class 2: from_check_result Method (orders 2050-2090)
# ============================================================================

class TestIterationOutcomeFromCheckResult:
    """Test IterationOutcome.from_check_result() conversion method."""

    @pytest.mark.order(2050)
    def test_from_check_result_detected_true_success_true(self):
        """Test conversion: detected=True, success=True -> REACHED."""
        print("\n=== Test: from_check_result(True, True) -> REACHED ===")

        result = IterationOutcome.from_check_result(detected=True, success=True)

        assert result == IterationOutcome.REACHED, \
            f"Expected REACHED, got {result}"
        assert result.value == "reached", \
            f"Expected 'reached', got '{result.value}'"
        print("[OK] (detected=True, success=True) -> REACHED")

    @pytest.mark.order(2060)
    def test_from_check_result_detected_false_success_true(self):
        """Test conversion: detected=False, success=True -> UNREACHED."""
        print("\n=== Test: from_check_result(False, True) -> UNREACHED ===")

        result = IterationOutcome.from_check_result(detected=False, success=True)

        assert result == IterationOutcome.UNREACHED, \
            f"Expected UNREACHED, got {result}"
        assert result.value == "unreached", \
            f"Expected 'unreached', got '{result.value}'"
        print("[OK] (detected=False, success=True) -> UNREACHED")

    @pytest.mark.order(2070)
    def test_from_check_result_detected_true_success_false(self):
        """Test conversion: detected=True, success=False -> FAILED."""
        print("\n=== Test: from_check_result(True, False) -> FAILED ===")

        result = IterationOutcome.from_check_result(detected=True, success=False)

        assert result == IterationOutcome.FAILED, \
            f"Expected FAILED, got {result}"
        assert result.value == "failed", \
            f"Expected 'failed', got '{result.value}'"
        print("[OK] (detected=True, success=False) -> FAILED")

    @pytest.mark.order(2080)
    def test_from_check_result_detected_false_success_false(self):
        """Test conversion: detected=False, success=False -> FAILED."""
        print("\n=== Test: from_check_result(False, False) -> FAILED ===")

        result = IterationOutcome.from_check_result(detected=False, success=False)

        assert result == IterationOutcome.FAILED, \
            f"Expected FAILED, got {result}"
        print("[OK] (detected=False, success=False) -> FAILED")

    @pytest.mark.order(2090)
    def test_from_check_result_preserves_enum_semantics(self):
        """Test that from_check_result returns actual enum members."""
        print("\n=== Test: from_check_result returns enum members ===")

        result1 = IterationOutcome.from_check_result(True, True)
        result2 = IterationOutcome.from_check_result(True, True)

        # Should return the same enum member (identity check)
        assert result1 is result2, "Should return same enum member instance"
        assert result1 is IterationOutcome.REACHED, "Should be the actual REACHED enum member"
        print("[OK] from_check_result returns actual enum members")


# ============================================================================
# Test Class 3: Enum Behavior (orders 2100-2130)
# ============================================================================

class TestIterationOutcomeEnumBehavior:
    """Test IterationOutcome enum behavior and operations."""

    @pytest.mark.order(2100)
    def test_enum_members_are_iterable(self):
        """Test that IterationOutcome members can be iterated."""
        print("\n=== Test: IterationOutcome is iterable ===")

        members = [member for member in IterationOutcome]

        assert len(members) == 4, f"Expected 4 members, got {len(members)}"
        assert IterationOutcome.REACHED in members
        assert IterationOutcome.UNREACHED in members
        assert IterationOutcome.FAILED in members
        assert IterationOutcome.SKIPPED in members
        print(f"[OK] All 4 members present: {[m.name for m in members]}")

    @pytest.mark.order(2110)
    def test_enum_members_are_unique(self):
        """Test that all enum members are unique instances."""
        print("\n=== Test: Enum members are unique ===")

        assert IterationOutcome.REACHED is not IterationOutcome.UNREACHED
        assert IterationOutcome.REACHED is not IterationOutcome.FAILED
        assert IterationOutcome.REACHED is not IterationOutcome.SKIPPED
        assert IterationOutcome.UNREACHED is not IterationOutcome.FAILED
        assert IterationOutcome.UNREACHED is not IterationOutcome.SKIPPED
        assert IterationOutcome.FAILED is not IterationOutcome.SKIPPED
        print("[OK] All enum members are unique instances")

    @pytest.mark.order(2120)
    def test_enum_equality_comparison(self):
        """Test IterationOutcome equality comparisons."""
        print("\n=== Test: Enum equality comparisons ===")

        # Same value should be equal
        assert IterationOutcome.REACHED == IterationOutcome.REACHED
        assert IterationOutcome.UNREACHED == IterationOutcome.UNREACHED

        # Different values should not be equal
        assert IterationOutcome.REACHED != IterationOutcome.UNREACHED
        assert IterationOutcome.REACHED != IterationOutcome.FAILED

        print("[OK] Enum equality works correctly")

    @pytest.mark.order(2130)
    def test_enum_string_representation(self):
        """Test IterationOutcome string representation."""
        print("\n=== Test: Enum string representation ===")

        # str() should give 'IterationOutcome.NAME'
        assert "IterationOutcome.REACHED" in str(IterationOutcome.REACHED)

        # repr() should give similar representation
        assert "IterationOutcome.REACHED" in repr(IterationOutcome.REACHED)

        # .value gives the actual string value
        assert IterationOutcome.REACHED.value == "reached"

        print("[OK] String representation works correctly")

    @pytest.mark.order(2140)
    def test_enum_access_by_name(self):
        """Test accessing enum members by name."""
        print("\n=== Test: Access enum by name ===")

        assert IterationOutcome["REACHED"] is IterationOutcome.REACHED
        assert IterationOutcome["UNREACHED"] is IterationOutcome.UNREACHED
        assert IterationOutcome["FAILED"] is IterationOutcome.FAILED
        assert IterationOutcome["SKIPPED"] is IterationOutcome.SKIPPED

        print("[OK] Can access enum members by name")

    @pytest.mark.order(2150)
    def test_enum_access_by_value(self):
        """Test accessing enum members by value."""
        print("\n=== Test: Access enum by value ===")

        assert IterationOutcome("reached") is IterationOutcome.REACHED
        assert IterationOutcome("unreached") is IterationOutcome.UNREACHED
        assert IterationOutcome("failed") is IterationOutcome.FAILED
        assert IterationOutcome("skipped") is IterationOutcome.SKIPPED

        print("[OK] Can access enum members by value")


# ============================================================================
# Test Class 4: Edge Cases (orders 2160-2180)
# ============================================================================

class TestIterationOutcomeEdgeCases:
    """Test IterationOutcome edge cases and error handling."""

    @pytest.mark.order(2160)
    def test_invalid_value_raises_error(self):
        """Test that invalid value raises ValueError."""
        print("\n=== Test: Invalid value raises error ===")

        with pytest.raises(ValueError):
            IterationOutcome("invalid_value")

        print("[OK] Invalid value raises ValueError")

    @pytest.mark.order(2170)
    def test_invalid_name_raises_error(self):
        """Test that invalid name raises KeyError."""
        print("\n=== Test: Invalid name raises error ===")

        with pytest.raises(KeyError):
            IterationOutcome["INVALID_NAME"]

        print("[OK] Invalid name raises KeyError")

    @pytest.mark.order(2180)
    def test_from_check_result_with_various_truthy_values(self):
        """Test from_check_result with various truthy/falsy values."""
        print("\n=== Test: from_check_result with truthy/falsy values ===")

        # Python treats various values as truthy/falsy
        assert IterationOutcome.from_check_result(1, 1) == IterationOutcome.REACHED
        assert IterationOutcome.from_check_result(0, 1) == IterationOutcome.UNREACHED
        assert IterationOutcome.from_check_result(1, 0) == IterationOutcome.FAILED
        assert IterationOutcome.from_check_result("text", True) == IterationOutcome.REACHED
        assert IterationOutcome.from_check_result([], True) == IterationOutcome.UNREACHED

        print("[OK] from_check_result handles truthy/falsy values correctly")


# ============================================================================
# Test Class 5: Use Case Scenarios (orders 2190-2210)
# ============================================================================

class TestIterationOutcomeUseCases:
    """Test realistic use case scenarios for IterationOutcome."""

    @pytest.mark.order(2190)
    def test_threshold_reached_scenario(self):
        """Test scenario: threshold was reached in probing."""
        print("\n=== Test: Threshold reached scenario ===")

        # Simulate executor returning detected=True, success=True
        outcome = IterationOutcome.from_check_result(detected=True, success=True)

        assert outcome == IterationOutcome.REACHED
        assert outcome.value == "reached"  # For markdown table output

        print("[OK] Threshold reached scenario works")

    @pytest.mark.order(2200)
    def test_threshold_not_reached_scenario(self):
        """Test scenario: threshold was not reached in probing."""
        print("\n=== Test: Threshold not reached scenario ===")

        # Simulate executor returning detected=False, success=True
        outcome = IterationOutcome.from_check_result(detected=False, success=True)

        assert outcome == IterationOutcome.UNREACHED
        assert outcome.value == "unreached"

        print("[OK] Threshold not reached scenario works")

    @pytest.mark.order(2210)
    def test_verification_failed_scenario(self):
        """Test scenario: verification failed (inconsistent results)."""
        print("\n=== Test: Verification failed scenario ===")

        # Simulate executor returning success=False (verification failed)
        outcome = IterationOutcome.from_check_result(detected=True, success=False)

        assert outcome == IterationOutcome.FAILED
        assert outcome.value == "failed"

        print("[OK] Verification failed scenario works")

    @pytest.mark.order(2220)
    def test_skipped_iteration_scenario(self):
        """Test scenario: iteration skipped (precision already met)."""
        print("\n=== Test: Skipped iteration scenario ===")

        # Algorithm decides not to call check() - use SKIPPED directly
        outcome = IterationOutcome.SKIPPED

        assert outcome.value == "skipped"
        # Note: SKIPPED cannot be created via from_check_result,
        # it's used directly by algorithms

        print("[OK] Skipped iteration scenario works")

    @pytest.mark.order(2230)
    def test_outcome_can_be_used_in_conditionals(self):
        """Test that outcomes can be used in conditional logic."""
        print("\n=== Test: Outcomes in conditional logic ===")

        outcome_reached = IterationOutcome.REACHED
        # outcome_unreached = IterationOutcome.UNREACHED
        outcome_failed = IterationOutcome.FAILED

        # Simulate algorithm decision based on outcome
        if outcome_reached == IterationOutcome.REACHED:
            result = "continue_upward"
        else:
            result = "other"

        assert result == "continue_upward"

        if outcome_failed == IterationOutcome.FAILED:
            result = "abort"
        else:
            result = "ok"

        assert result == "abort"

        print("[OK] Outcomes work in conditional logic")
