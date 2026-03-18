#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit Tests for PFC XOFF Probing

Tests sim executor behavior without PTF dependency.
Covers normal and abnormal scenarios.
"""

import pytest
import sys
import os

# Add probe directory to path
probe_dir = os.path.join(os.path.dirname(__file__), '../../probe')
sys.path.insert(0, probe_dir)

from sim_pfc_xoff_probing_executor import (  # noqa: E402, F401
    SimPfcXoffProbingExecutor,
    SimPfcXoffProbingExecutorNoisy,
    SimPfcXoffProbingExecutorWrongConfig,
    SimPfcXoffProbingExecutorIntermittent,
    SimPfcXoffProbingExecutorBadSpot
)


@pytest.mark.order(3)
def test_pfc_xoff_normal_scenario(mock_observer):
    """
    UT #1: PFC XOFF - Normal scenario

    Test normal sim executor with deterministic behavior.
    Expected: Threshold at 500 packets detected correctly.
    """
    print("\n=== Testing PFC XOFF Normal Scenario ===")
    executor = SimPfcXoffProbingExecutor(
        observer=mock_observer,
        name='test_pfc',
        actual_threshold=500
    )

    # Below threshold - should not trigger
    result1 = executor.check(None, None, 400)[1]  # check() returns (success, detected)
    print(f"  Check at 400 packets: {'TRIGGERED' if result1 else 'NOT triggered'} (expected: NOT triggered)")
    assert not result1

    result2 = executor.check(None, None, 499)[1]
    print(f"  Check at 499 packets: {'TRIGGERED' if result2 else 'NOT triggered'} (expected: NOT triggered)")
    assert not result2

    # At threshold - should trigger
    result3 = executor.check(None, None, 500)[1]
    print(f"  Check at 500 packets: {'TRIGGERED' if result3 else 'NOT triggered'} (expected: TRIGGERED)")
    assert result3

    # Above threshold - should trigger
    result4 = executor.check(None, None, 600)[1]
    print(f"  Check at 600 packets: {'TRIGGERED' if result4 else 'NOT triggered'} (expected: TRIGGERED)")
    assert result4

    result5 = executor.check(None, None, 1000)[1]
    print(f"  Check at 1000 packets: {'TRIGGERED' if result5 else 'NOT triggered'} (expected: TRIGGERED)")
    assert result5

    # Verify check count
    print(f"\nTotal checks performed: {executor._check_count}")
    assert executor._check_count == 5

    # Cleanup
    executor.cleanup()

    print("[OK] PFC XOFF normal scenario test passed")


@pytest.mark.order(4)
def test_pfc_xoff_noisy_hardware(mock_observer):
    """
    UT #2: PFC XOFF - Noisy hardware (Abnormal scenario)

    Test noisy executor with random fluctuation.
    Expected: Behavior is non-deterministic around threshold due to noise.
    """
    executor = SimPfcXoffProbingExecutorNoisy(
        observer=mock_observer,
        name='test_pfc_noisy',
        actual_threshold=500,
        noise_level=10  # ±10 packets noise
    )

    # Far below threshold - should always fail (even with noise)
    results_far_below = [executor.check(None, None, 400)[1] for _ in range(10)]
    assert not any(results_far_below), "Far below threshold should never trigger"

    # At threshold boundary (495) - should be noisy
    results_boundary = [executor.check(None, None, 495)[1] for _ in range(100)]

    # With noise_level=10, at 495:
    # - Min effective = 495-10 = 485 (< 500, no trigger)
    # - Max effective = 495+10 = 505 (> 500, trigger)
    # So should see both True and False
    assert any(results_boundary), "Should trigger sometimes with positive noise"
    assert not all(results_boundary), "Should not trigger always"

    # Far above threshold - should always trigger (even with noise)
    results_far_above = [executor.check(None, None, 600)[1] for _ in range(10)]
    assert all(results_far_above), "Far above threshold should always trigger"

    # Cleanup
    executor.cleanup()

    print("[OK] PFC XOFF noisy hardware test passed")


@pytest.mark.order(5)
def test_pfc_xoff_bad_spot_normal_values(mock_observer):
    """
    UT #3: PFC XOFF - Bad-spot executor with normal (non-bad) values

    Test that bad-spot executor behaves like normal executor for
    values NOT in the bad_values set.
    """
    print("\n=== Testing PFC XOFF Bad-Spot: Normal Values ===")
    executor = SimPfcXoffProbingExecutorBadSpot(
        observer=mock_observer,
        name='test_pfc_bad_spot',
        actual_threshold=500,
        bad_values=[300, 375]
    )

    # Below threshold, not a bad value — should not trigger
    success, detected = executor.check(None, None, 400)
    print(f"  Check at 400: success={success}, detected={detected}")
    assert success is True
    assert detected is False

    # At threshold, not a bad value — should trigger
    success, detected = executor.check(None, None, 500)
    print(f"  Check at 500: success={success}, detected={detected}")
    assert success is True
    assert detected is True

    # Above threshold — should trigger
    success, detected = executor.check(None, None, 600)
    print(f"  Check at 600: success={success}, detected={detected}")
    assert success is True
    assert detected is True

    assert executor.bad_hit_count == 0, "No bad values should have been hit"
    executor.cleanup()
    print("[OK] Bad-spot normal values test passed")


@pytest.mark.order(6)
def test_pfc_xoff_bad_spot_bad_values(mock_observer):
    """
    UT #4: PFC XOFF - Bad-spot executor always fails at bad values

    Test that bad-spot executor returns (False, False) for values
    in the bad_values set, regardless of threshold.
    """
    print("\n=== Testing PFC XOFF Bad-Spot: Bad Values ===")
    executor = SimPfcXoffProbingExecutorBadSpot(
        observer=mock_observer,
        name='test_pfc_bad_spot',
        actual_threshold=500,
        bad_values=[300, 375]
    )

    # Bad value below threshold — should fail verification
    success, detected = executor.check(None, None, 300)
    print(f"  Check at 300 (bad): success={success}, detected={detected}")
    assert success is False
    assert detected is False

    # Bad value below threshold — should fail verification
    success, detected = executor.check(None, None, 375)
    print(f"  Check at 375 (bad): success={success}, detected={detected}")
    assert success is False
    assert detected is False

    # Normal value — should work fine
    success, detected = executor.check(None, None, 400)
    print(f"  Check at 400 (normal): success={success}, detected={detected}")
    assert success is True

    assert executor.bad_hit_count == 2, f"Should have hit 2 bad values, got {executor.bad_hit_count}"
    executor.cleanup()
    print("[OK] Bad-spot bad values test passed")


@pytest.mark.order(7)
def test_pfc_xoff_bad_spot_empty_bad_values(mock_observer):
    """
    UT #5: PFC XOFF - Bad-spot executor with no bad values acts like normal

    When bad_values is empty, executor should behave identically to
    the normal SimPfcXoffProbingExecutor.
    """
    print("\n=== Testing PFC XOFF Bad-Spot: Empty Bad Values ===")
    executor = SimPfcXoffProbingExecutorBadSpot(
        observer=mock_observer,
        name='test_pfc_bad_spot',
        actual_threshold=500,
        bad_values=[]
    )

    # Below threshold
    assert executor.check(None, None, 400) == (True, False)
    # At threshold
    assert executor.check(None, None, 500) == (True, True)
    # Above threshold
    assert executor.check(None, None, 600) == (True, True)

    assert executor.bad_hit_count == 0
    executor.cleanup()
    print("[OK] Bad-spot empty bad values test passed")


@pytest.mark.order(8)
def test_pfc_xoff_bad_spot_repeated_bad_checks(mock_observer):
    """
    UT #6: PFC XOFF - Bad-spot executor tracks hit count correctly

    Multiple checks at the same bad value should all fail and
    increment the hit counter.
    """
    print("\n=== Testing PFC XOFF Bad-Spot: Repeated Bad Checks ===")
    executor = SimPfcXoffProbingExecutorBadSpot(
        observer=mock_observer,
        name='test_pfc_bad_spot',
        actual_threshold=500,
        bad_values=[300]
    )

    for i in range(5):
        success, detected = executor.check(None, None, 300)
        assert success is False and detected is False, f"Check #{i+1} at bad value should fail"

    assert executor.bad_hit_count == 5, f"Should have 5 bad hits, got {executor.bad_hit_count}"
    print(f"  Bad value 300 tested 5 times, all failed (hit_count={executor.bad_hit_count})")
    executor.cleanup()
    print("[OK] Bad-spot repeated checks test passed")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
