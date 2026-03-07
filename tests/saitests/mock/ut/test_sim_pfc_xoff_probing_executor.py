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
    SimPfcXoffProbingExecutorIntermittent
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


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
