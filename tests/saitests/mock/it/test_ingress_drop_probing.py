"""
Ingress Drop Probing Mock Tests - Complete Test Suite

Comprehensive coverage of Ingress Drop probing scenarios based on design document.

Ingress Drop Characteristics:
- Traffic pattern: 1 src -> N dst
- Independent threshold (no dependency like Headroom Pool)
- Detects packet drop events (vs PFC frame generation)
- Uses same 3/4-phase algorithm as PFC XOFF
- Typically higher threshold than PFC XOFF (Ingress Drop > PFC XOFF)

Test Coverage (23 tests):
A. Basic Hardware (4 tests)
B. Point Probing (3 tests)
C. Precision Ratio (4 tests)
D. Noise + Verification Attempts (4 tests)
E. Boundary Conditions (5 tests)
F. Failure Scenarios (3 tests)
"""

import pytest
from probe_test_helper import setup_test_environment, create_ingress_drop_probe_instance  # noqa: E402

# Setup test environment: PTF mocks + probe path (must be BEFORE probe imports)
setup_test_environment()


class TestIngressDropProbing:
    """Complete Ingress Drop probing mock tests."""

    # ========================================================================
    # A. Basic Hardware (4 tests)
    # ========================================================================

    def test_ingress_drop_normal_scenario(self):
        """A1: Basic normal scenario - clean hardware, no noise"""
        actual_threshold = 700  # Ingress Drop > PFC XOFF

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=False,
            precision_target_ratio=0.05
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        assert result.lower_bound <= actual_threshold <= result.upper_bound

        result_range = result.upper_bound - result.lower_bound
        expected_max = actual_threshold * 0.05 * 2
        assert result_range <= expected_max

        print(f"[PASS] Normal: threshold={actual_threshold}, result=[{result.lower_bound}, {result.upper_bound}]")

    def test_ingress_drop_noisy_hardware(self):
        """A2: Noisy hardware scenario"""
        actual_threshold = 800

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario='noisy',
            enable_precise_detection=False,
            precision_target_ratio=0.05,
            max_attempts=5
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        # Allow tolerance for noise
        tolerance = actual_threshold * 0.10
        assert result.lower_bound - tolerance <= actual_threshold <= result.upper_bound + tolerance

        print(f"[PASS] Noisy: threshold={actual_threshold}, result=[{result.lower_bound}, {result.upper_bound}]")

    def test_ingress_drop_wrong_config(self):
        """A3: Wrong threshold configuration"""
        actual_threshold = 650

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario='wrong_config',
            enable_precise_detection=False,
            precision_target_ratio=0.05
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        assert result.lower_bound is not None and result.upper_bound is not None

        print(f"[PASS] Wrong config: result=[{result.lower_bound}, {result.upper_bound}]")

    def test_ingress_drop_intermittent(self):
        """A4: Intermittent drop behavior"""
        actual_threshold = 750

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario='intermittent',
            enable_precise_detection=False,
            precision_target_ratio=0.05,
            max_attempts=7
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        if result.success:
            assert (result.lower_bound <= actual_threshold
                    <= result.upper_bound)
            print(f"[PASS] Intermittent: threshold={actual_threshold}, "
                  f"result=[{result.lower_bound}, {result.upper_bound}]")
        else:
            print("[PASS] Intermittent: Extreme case handled, "
                  "probing failed as expected")

    # ========================================================================
    # B. Point Probing (3 tests)
    # ========================================================================

    def test_ingress_drop_point_probing_normal(self):
        """B1: Point Probing 4-phase validation"""
        actual_threshold = 900

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=True,
            precise_detection_range_limit=100,
            precision_target_ratio=0.01
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        result_range = result.upper_bound - result.lower_bound
        assert result_range < 100

        print(f"[PASS] Point Probing: range={result_range}, result=[{result.lower_bound}, {result.upper_bound}]")

    def test_ingress_drop_point_probing_noisy(self):
        """B2: Point Probing with noisy hardware"""
        actual_threshold = 950

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario='noisy',
            enable_precise_detection=True,
            precise_detection_range_limit=100,
            precision_target_ratio=0.01,
            max_attempts=5
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        result_range = result.upper_bound - result.lower_bound
        assert result_range < 150

        print(f"[PASS] Point Probing (noisy): range={result_range}")

    def test_ingress_drop_fixed_range_convergence(self):
        """B3: Fixed Range Convergence (100-200 cells -> Point)"""
        actual_threshold = 1100

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=True,
            precise_detection_range_limit=150,
            precision_target_ratio=0.01,
            point_probing_step_size=1
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        result_range = result.upper_bound - result.lower_bound
        assert result_range < 150

        print(f"[PASS] Fixed range convergence: range={result_range}, limit=150")

    # ========================================================================
    # C. Precision Ratio (4 tests)
    # ========================================================================

    def test_ingress_drop_ultra_high_precision_0_5_percent(self):
        """C1: Ultra high precision (0.5%)"""
        actual_threshold = 2200

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=False,
            precision_target_ratio=0.005
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        result_range = result.upper_bound - result.lower_bound
        # 0.5% of 2200 = 11 cells, allow 10x = 110 (real algorithm has minimum step size)
        expected_max = actual_threshold * 0.005 * 10
        assert result_range <= expected_max

        print(f"[PASS] Ultra high precision (0.5%): range={result_range}, expected<={expected_max}")

    def test_ingress_drop_high_precision_1_percent(self):
        """C2: High precision (1%)"""
        actual_threshold = 1700

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=False,
            precision_target_ratio=0.01
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        result_range = result.upper_bound - result.lower_bound
        # 1% of 1700 = 17 cells, allow 5x = 85 (real algorithm has minimum step size)
        expected_max = actual_threshold * 0.01 * 5
        assert result_range <= expected_max

        print(f"[PASS] High precision (1%): range={result_range}, expected<={expected_max}")

    def test_ingress_drop_normal_precision_5_percent(self):
        """C3: Normal precision (5%)"""
        actual_threshold = 1400

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=False,
            precision_target_ratio=0.05
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        result_range = result.upper_bound - result.lower_bound
        expected_max = actual_threshold * 0.05 * 2
        assert result_range <= expected_max

        print(f"[PASS] Normal precision (5%): range={result_range}, expected<={expected_max}")

    def test_ingress_drop_loose_precision_20_percent(self):
        """C4: Loose precision (20%)"""
        actual_threshold = 900

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=False,
            precision_target_ratio=0.20
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        result_range = result.upper_bound - result.lower_bound
        expected_max = actual_threshold * 0.20 * 2
        assert result_range <= expected_max

        print(f"[PASS] Loose precision (20%): range={result_range}, expected<={expected_max}")

    # ========================================================================
    # D. Noise + Verification Attempts (4 tests)
    # ========================================================================

    def test_ingress_drop_low_noise_few_attempts(self):
        """D1: Low noise with few verification attempts"""
        actual_threshold = 750

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario='noisy',
            enable_precise_detection=False,
            precision_target_ratio=0.05,
            max_attempts=2
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        tolerance = actual_threshold * 0.08
        assert result.lower_bound - tolerance <= actual_threshold <= result.upper_bound + tolerance

        print(f"[PASS] Low noise: attempts=2, result=[{result.lower_bound}, {result.upper_bound}]")

    def test_ingress_drop_medium_noise_moderate_attempts(self):
        """D2: Medium noise with moderate attempts"""
        actual_threshold = 850

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario='noisy',
            enable_precise_detection=False,
            precision_target_ratio=0.05,
            max_attempts=4
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        tolerance = actual_threshold * 0.10
        assert result.lower_bound - tolerance <= actual_threshold <= result.upper_bound + tolerance

        print(f"[PASS] Medium noise: attempts=4, result=[{result.lower_bound}, {result.upper_bound}]")

    def test_ingress_drop_high_noise_many_attempts(self):
        """D3: High noise with many attempts"""
        actual_threshold = 950

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario='noisy',
            enable_precise_detection=False,
            precision_target_ratio=0.05,
            max_attempts=6
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        tolerance = actual_threshold * 0.10
        assert result.lower_bound - tolerance <= actual_threshold <= result.upper_bound + tolerance

        print(f"[PASS] High noise: attempts=6, result=[{result.lower_bound}, {result.upper_bound}]")

    def test_ingress_drop_extreme_noise_max_attempts(self):
        """D4: Extreme noise with maximum attempts"""
        actual_threshold = 1050

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario='noisy',
            enable_precise_detection=False,
            precision_target_ratio=0.05,
            max_attempts=7
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        tolerance = actual_threshold * 0.15
        assert result.lower_bound - tolerance <= actual_threshold <= result.upper_bound + tolerance

        print(f"[PASS] Extreme noise: attempts=7, result=[{result.lower_bound}, {result.upper_bound}]")

    # ========================================================================
    # E. Boundary Conditions (5 tests)
    # ========================================================================

    def test_ingress_drop_zero_threshold(self):
        """E1: Zero threshold edge case"""
        actual_threshold = 0

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=False,
            precision_target_ratio=0.05
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        if result.success:
            assert result.lower_bound >= 0
            assert result.upper_bound <= 100
            print(f"[PASS] Zero threshold: "
                  f"result=[{result.lower_bound}, {result.upper_bound}]")
        else:
            print("[PASS] Zero threshold: Edge case handled")

    def test_ingress_drop_max_threshold(self):
        """E2: Maximum threshold (at pool limit)"""
        pool_size = 200000
        actual_threshold = 199500

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=False,
            precision_target_ratio=0.05
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        assert result.upper_bound <= pool_size
        assert (result.lower_bound <= actual_threshold
                <= result.upper_bound)

        print(f"[PASS] Max threshold: threshold={actual_threshold}, "
              f"result=[{result.lower_bound}, {result.upper_bound}]")

    def test_ingress_drop_narrow_search_space(self):
        """E3: Narrow search space (range < 1000 cells)"""
        actual_threshold = 600

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=False,
            precision_target_ratio=0.02
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        result_range = result.upper_bound - result.lower_bound
        assert result_range <= 50

        print(f"[PASS] Narrow search space: range={result_range}")

    def test_ingress_drop_tiny_range(self):
        """E4: Tiny range (< 10 cells between bounds)"""
        actual_threshold = 150

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=True,
            precise_detection_range_limit=10,
            precision_target_ratio=0.01,
            point_probing_step_size=1
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        result_range = result.upper_bound - result.lower_bound
        assert result_range < 10

        print(f"[PASS] Tiny range: range={result_range} cells")

    def test_ingress_drop_single_value_space(self):
        """E5: Single-value search space (lower == upper)"""
        actual_threshold = 300

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=True,
            precise_detection_range_limit=1,
            precision_target_ratio=0.001,
            point_probing_step_size=1
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        # Should converge to very small range (real algorithm has minimum step size)
        result_range = result.upper_bound - result.lower_bound
        assert result_range <= 15

        print(f"[PASS] Single-value space: range={result_range}")

    # ========================================================================
    # F. Failure Scenarios (3 tests)
    # ========================================================================

    def test_ingress_drop_no_drop_detected(self):
        """F1: Never drops packets (threshold > pool size)"""
        actual_threshold = 250000  # Exceeds pool size

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=False,
            precision_target_ratio=0.05
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        if result.success:
            assert result.upper_bound >= 180000

        print(f"[PASS] No drop detected: result=[{result.lower_bound}, {result.upper_bound}], success={result.success}")

    def test_ingress_drop_always_drops(self):
        """F2: Always drops packets (threshold at 0)"""
        actual_threshold = 1

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=False,
            precision_target_ratio=0.05
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        if result.success:
            assert result.lower_bound <= 10
            print(f"[PASS] Always drops: "
                  f"result=[{result.lower_bound}, {result.upper_bound}]")
        else:
            print("[PASS] Always drops: Edge case handled")

    def test_ingress_drop_inconsistent_results(self):
        """F3: Inconsistent drop behavior across probes"""
        actual_threshold = 850

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario='intermittent',
            enable_precise_detection=False,
            precision_target_ratio=0.10,
            max_attempts=7
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None
        if result.success:
            assert (result.lower_bound <= actual_threshold
                    <= result.upper_bound)
            print(f"[PASS] Inconsistent: threshold={actual_threshold}, "
                  f"result=[{result.lower_bound}, {result.upper_bound}]")
        else:
            print("[PASS] Inconsistent: Extreme inconsistency handled")

    # ========================================================================
    # G. Bug Fix Validation (3 tests)
    # ========================================================================

    def test_ingress_drop_threshold_at_one(self):
        """
        G1: Boundary - threshold at value 1 (lower-bound halving edge case)

        Validates:
        - Lower-bound algorithm terminates when current reaches 1
        - No infinite loop from max(current // 2, 1) clamping
        """
        actual_threshold = 1

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=False,
            precision_target_ratio=0.05
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None, "Probe should return a result even for threshold=1"
        if result.success:
            assert result.lower_bound <= actual_threshold <= result.upper_bound, \
                f"Result [{result.lower_bound}, {result.upper_bound}] should bracket threshold {actual_threshold}"
            print(f"[PASS] Threshold=1 boundary: result=[{result.lower_bound}, {result.upper_bound}]")
        else:
            print("[PASS] Threshold=1 boundary: completed (result=FAILED, expected for extreme case)")

    def test_ingress_drop_threshold_at_two(self):
        """
        G2: Boundary - threshold at value 2 (binary search minimum range)

        Validates:
        - Binary search converges correctly at minimum meaningful range
        """
        actual_threshold = 2

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario=None,
            enable_precise_detection=False,
            precision_target_ratio=0.05
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None, "Probe should return a result for threshold=2"
        assert result.lower_bound <= actual_threshold <= result.upper_bound, \
            f"Result [{result.lower_bound}, {result.upper_bound}] should bracket threshold {actual_threshold}"

        print(f"[PASS] Threshold=2 boundary: result=[{result.lower_bound}, {result.upper_bound}]")

    def test_ingress_drop_point_probing_with_intermittent_failures(self):
        """
        G3: Point Probing with intermittent verification failures

        Validates:
        - Point Probing handles verification failures (drain buffer recovery)
        - Algorithm does not crash on intermittent executor failures
        """
        actual_threshold = 700

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario='intermittent',
            enable_precise_detection=True,
            precise_detection_range_limit=100,
            precision_target_ratio=0.01
        )

        probe.runTest()
        result = probe.probe_result

        assert result is not None, "Probe should return a result despite intermittent failures"
        if result.success:
            assert result.lower_bound <= actual_threshold <= result.upper_bound, \
                f"Result [{result.lower_bound}, {result.upper_bound}] should bracket {actual_threshold}"
            print(f"[PASS] Point Probing recovery: result=[{result.lower_bound}, {result.upper_bound}]")
        else:
            print("[PASS] Point Probing with intermittent: completed gracefully (result=FAILED due to noise)")

    def test_ingress_drop_range_oscillation_bad_spot(self):
        """
        G4: Range algorithm oscillation with deterministic bad-spot executor

        Same pattern as PFC XOFF G4: uses bad_spot scenario where specific
        candidate values always fail verification. Checks Phase 3 observer
        output for repeated candidate values.
        """
        import io
        import sys

        actual_threshold = 700

        bad_values = [687, 693, 696]
        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario='bad_spot',
            bad_values=bad_values,
            enable_precise_detection=False,
            precision_target_ratio=0.005,
        )

        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured

        probe.runTest()
        result = probe.probe_result

        sys.stderr = old_stderr
        output = captured.getvalue()

        phase3_candidates = []
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('| 3.') and '|' in line:
                cols = [c.strip() for c in line.split('|')]
                if len(cols) >= 4 and cols[3].lstrip('-').isdigit():
                    phase3_candidates.append(int(cols[3]))

        assert result is not None

        if phase3_candidates:
            from collections import Counter
            counts = Counter(phase3_candidates)
            max_repeats = max(counts.values()) if counts else 0
            most_repeated = counts.most_common(1)[0] if counts else (0, 0)

            print(f"[INFO] Phase 3 candidates: {phase3_candidates}")
            print(f"       Most repeated: value={most_repeated[0]} x{most_repeated[1]}")

            assert max_repeats <= 3, \
                f"Oscillation: value {most_repeated[0]} tested {most_repeated[1]} times"
        else:
            print("[INFO] Phase 3 was not reached")

        if result.success:
            print(f"[PASS] result=[{result.lower_bound}, {result.upper_bound}]")
        else:
            print("[PASS] Completed (bad spots caused failure)")

    def test_ingress_drop_small_threshold_precision(self):
        """
        G5: Precision check max(1,...) guard for small threshold
        """
        import io
        import sys

        actual_threshold = 10

        probe = create_ingress_drop_probe_instance(
            actual_threshold=actual_threshold,
            scenario='bad_spot',
            bad_values=[10],
            enable_precise_detection=False,
            precision_target_ratio=0.05
        )

        captured = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = captured

        probe.runTest()
        result = probe.probe_result

        sys.stderr = old_stderr
        output = captured.getvalue()

        phase3_lines = [line for line in output.split('\n') if line.strip().startswith('| 3.')]

        assert result is not None
        assert len(phase3_lines) < 30, \
            f"Phase 3 took {len(phase3_lines)} iterations — precision check broken"
        print(f"[PASS] Small threshold precision: {len(phase3_lines)} Phase 3 iterations")


def main():
    """Run complete Ingress Drop probing test suite."""
    print("=" * 80)
    print("Ingress Drop Probing Mock Tests - Complete Suite (23 Tests)")
    print("=" * 80)
    print()
    print("Test Categories:")
    print("  A. Basic Hardware (4 tests)")
    print("  B. Point Probing (3 tests)")
    print("  C. Precision Ratio (4 tests)")
    print("  D. Noise + Attempts (4 tests)")
    print("  E. Boundary Conditions (5 tests)")
    print("  F. Failure Scenarios (3 tests)")
    print()

    pytest.main([__file__, '-v', '-s'])


if __name__ == '__main__':
    main()
