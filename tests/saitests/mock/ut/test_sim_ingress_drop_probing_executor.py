#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit Tests for Ingress Drop Probing

Tests sim executor behavior without PTF dependency.
Covers normal and abnormal scenarios.
"""

import pytest
import sys
import os

# Add probe directory to path
probe_dir = os.path.join(os.path.dirname(__file__), '../../probe')
sys.path.insert(0, probe_dir)

from sim_ingress_drop_probing_executor import (  # noqa: E402, F401
    SimIngressDropProbingExecutor,
    SimIngressDropProbingExecutorNoisy,
    SimIngressDropProbingExecutorWrongConfig,
    SimIngressDropProbingExecutorIntermittent,
    SimIngressDropProbingExecutorBadSpot
)


@pytest.mark.order(5)
def test_ingress_drop_normal_scenario(mock_observer):
    """
    UT #3: Ingress Drop - Normal scenario

    Test normal sim executor with deterministic behavior.
    Expected: Threshold at 500 packets detected correctly.
    """
    print("\n=== Testing Ingress Drop Normal Scenario ===")
    executor = SimIngressDropProbingExecutor(
        observer=mock_observer,
        name='test_ingress_drop',
        actual_threshold=500
    )

    # Below threshold - should not drop
    result1 = executor.check(None, None, 400)[1]  # check() returns (success, detected)
    print(f"  Check at 400 packets: {'DROP' if result1 else 'NO drop'} (expected: NO drop)")
    assert not result1

    result2 = executor.check(None, None, 499)[1]
    print(f"  Check at 499 packets: {'DROP' if result2 else 'NO drop'} (expected: NO drop)")
    assert not result2

    # At threshold - should drop
    result3 = executor.check(None, None, 500)[1]
    print(f"  Check at 500 packets: {'DROP' if result3 else 'NO drop'} (expected: DROP)")
    assert result3

    # Above threshold - should drop
    result4 = executor.check(None, None, 600)[1]
    print(f"  Check at 600 packets: {'DROP' if result4 else 'NO drop'} (expected: DROP)")
    assert result4

    result5 = executor.check(None, None, 1000)[1]
    print(f"  Check at 1000 packets: {'DROP' if result5 else 'NO drop'} (expected: DROP)")
    assert result5

    # Verify check count
    print(f"\nTotal checks performed: {executor._check_count}")
    assert executor._check_count == 5

    # Cleanup
    executor.cleanup()

    print("[OK] Ingress Drop normal scenario test passed")


@pytest.mark.order(6)
def test_ingress_drop_wrong_config(mock_observer):
    """
    UT #4: Ingress Drop - Wrong configuration (Abnormal scenario)

    Test wrong config executor with threshold offset.
    Expected: Effective threshold shifted by offset.
    """
    print("\n=== Testing Ingress Drop Wrong Config Scenario ===")
    executor = SimIngressDropProbingExecutorWrongConfig(
        observer=mock_observer,
        name='test_ingress_drop_wrong',
        actual_threshold=500,
        offset=100  # Effective threshold = 600
    )

    print("Configured threshold: 500, Offset: +100 -> Effective threshold: 600")
    print("\nTesting behavior:")

    # Below effective threshold (500+100=600) - should not drop
    # check() returns (success, detected)
    result1 = executor.check(None, None, 500)[1]
    print(f"  Check at 500 packets (configured threshold): "
          f"{'DROP' if result1 else 'NO drop'} "
          f"(expected: NO drop due to offset)")
    assert not result1

    result2 = executor.check(None, None, 599)[1]
    print(f"  Check at 599 packets: {'DROP' if result2 else 'NO drop'} (expected: NO drop)")
    assert not result2

    # At effective threshold - should drop
    result3 = executor.check(None, None, 600)[1]
    print(f"  Check at 600 packets (effective threshold): {'DROP' if result3 else 'NO drop'} (expected: DROP)")
    assert result3

    # Above effective threshold - should drop
    result4 = executor.check(None, None, 700)[1]
    print(f"  Check at 700 packets: {'DROP' if result4 else 'NO drop'} (expected: DROP)")
    assert result4

    # Verify behavior difference from normal executor
    print("\nComparing with normal executor (no offset):")
    normal_executor = SimIngressDropProbingExecutor(
        observer=mock_observer,
        name='test_normal',
        actual_threshold=500
    )

    # At actual_threshold=500: normal drops, wrong_config doesn't
    normal_result = normal_executor.check(None, None, 500)[1]
    wrong_result = executor.check(None, None, 500)[1]
    print(f"  At 500 packets: Normal={'DROP' if normal_result else 'NO drop'}, "
          f"WrongConfig={'DROP' if wrong_result else 'NO drop'}")
    assert normal_result  # Drops
    assert not wrong_result     # Doesn't drop (needs 600)

    # Cleanup
    executor.cleanup()
    normal_executor.cleanup()

    print("[OK] Ingress Drop wrong configuration test passed (detected offset behavior)")


@pytest.mark.order(7)
def test_ingress_drop_bad_spot_normal_values(mock_observer):
    """
    UT: Ingress Drop Bad-spot executor with normal (non-bad) values

    Behaves like normal executor for values not in bad_values set.
    """
    print("\n=== Testing Ingress Drop Bad-Spot: Normal Values ===")
    executor = SimIngressDropProbingExecutorBadSpot(
        observer=mock_observer,
        name='test_drop_bad_spot',
        actual_threshold=500,
        bad_values=[300, 375]
    )

    success, detected = executor.check(None, None, 400)
    assert success is True and detected is False

    success, detected = executor.check(None, None, 500)
    assert success is True and detected is True

    success, detected = executor.check(None, None, 600)
    assert success is True and detected is True

    assert executor.bad_hit_count == 0
    executor.cleanup()
    print("[OK] Ingress Drop bad-spot normal values test passed")


@pytest.mark.order(8)
def test_ingress_drop_bad_spot_bad_values(mock_observer):
    """
    UT: Ingress Drop Bad-spot executor always fails at bad values
    """
    print("\n=== Testing Ingress Drop Bad-Spot: Bad Values ===")
    executor = SimIngressDropProbingExecutorBadSpot(
        observer=mock_observer,
        name='test_drop_bad_spot',
        actual_threshold=500,
        bad_values=[300, 375]
    )

    success, detected = executor.check(None, None, 300)
    assert success is False and detected is False

    success, detected = executor.check(None, None, 375)
    assert success is False and detected is False

    # Normal value still works
    success, detected = executor.check(None, None, 400)
    assert success is True

    assert executor.bad_hit_count == 2
    executor.cleanup()
    print("[OK] Ingress Drop bad-spot bad values test passed")


@pytest.mark.order(9)
def test_ingress_drop_bad_spot_empty(mock_observer):
    """
    UT: Ingress Drop Bad-spot with empty bad_values acts like normal
    """
    executor = SimIngressDropProbingExecutorBadSpot(
        observer=mock_observer,
        name='test_drop_bad_spot',
        actual_threshold=500,
        bad_values=[]
    )

    assert executor.check(None, None, 400) == (True, False)
    assert executor.check(None, None, 500) == (True, True)
    assert executor.bad_hit_count == 0
    executor.cleanup()
    print("[OK] Ingress Drop bad-spot empty test passed")


@pytest.mark.order(10)
def test_ingress_drop_bad_spot_repeated(mock_observer):
    """
    UT: Ingress Drop Bad-spot tracks repeated hits
    """
    executor = SimIngressDropProbingExecutorBadSpot(
        observer=mock_observer,
        name='test_drop_bad_spot',
        actual_threshold=500,
        bad_values=[300]
    )

    for _ in range(5):
        success, detected = executor.check(None, None, 300)
        assert success is False and detected is False

    assert executor.bad_hit_count == 5
    executor.cleanup()
    print("[OK] Ingress Drop bad-spot repeated test passed")


@pytest.mark.order(14)
def test_ingress_drop_intermittent_returns_tuple_not_exception(mock_observer):
    """
    Bug: Intermittent executor raises Exception instead of returning (False, False).

    Physical executors catch hardware errors and return (False, False).
    Algorithm callers do not use try/except — they expect a tuple and check
    'if not success:' to handle failures. Raising breaks the contract.
    """
    executor = SimIngressDropProbingExecutorIntermittent(
        observer=mock_observer,
        name='test_intermittent',
        actual_threshold=500,
        failure_rate=1.0  # 100% failure — every check() fails
    )

    # Should return (False, False), NOT raise Exception
    success, detected = executor.check(None, None, 500)
    assert success is False
    assert detected is False

    executor.cleanup()
    print("[OK] Intermittent executor returns (False, False) on failure")


@pytest.mark.order(15)
def test_ingress_drop_intermittent_success_path(mock_observer):
    """Intermittent executor normal path (no failure) returns correct result."""
    executor = SimIngressDropProbingExecutorIntermittent(
        observer=mock_observer,
        name='test_intermittent_ok',
        actual_threshold=500,
        failure_rate=0.0  # 0% failure — every check() succeeds
    )

    success, detected = executor.check(None, None, 600)
    assert success is True
    assert detected is True  # 600 >= 500

    success, detected = executor.check(None, None, 400)
    assert success is True
    assert detected is False  # 400 < 500

    executor.cleanup()
    print("[OK] Intermittent executor success path works correctly")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
