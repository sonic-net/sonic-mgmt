#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sim PFC Xoff Executors - Simulated PFC behavior for testing

Provides multiple sim executor implementations for different test scenarios:
- SimPfcXoffExecutor: Normal sim executor
- SimPfcXoffExecutorNoisy: Simulates hardware with random noise
- SimPfcXoffExecutorWrongConfig: Simulates wrong threshold configuration
- SimPfcXoffExecutorIntermittent: Simulates intermittent hardware failures

Usage:
    # Normal sim
    executor = ExecutorRegistry.create('pfc_xoff', 'sim',
                                       observer=obs, name='port12')

    # Noisy sim
    executor = ExecutorRegistry.create('pfc_xoff', 'sim',
                                       scenario='noisy', noise_level=10,
                                       observer=obs, name='port12')
"""

import random
from executor_registry import ExecutorRegistry


@ExecutorRegistry.register(probe_type='pfc_xoff', executor_env='sim')
class SimPfcXoffProbingExecutor:
    """
    Normal sim executor for PFC XOFF detection.

    Simulates ideal hardware behavior:
    - Deterministic PFC trigger detection
    - No noise or errors
    - Predictable threshold behavior
    """

    def __init__(self, observer, name, ptftest=None, verbose=True, actual_threshold=500, **kwargs):
        """
        Initialize mock PFC XOFF executor.

        Args:
            observer: ProbingObserver instance
            name: Executor name for logging
            ptftest: PTF test instance (not used in mock)
            verbose: Enable verbose logging
            actual_threshold: Simulated actual threshold value (packets)
            **kwargs: Additional parameters (ignored in Normal sim)
        """
        self.observer = observer
        self.name = name
        self.ptftest = ptftest
        self.verbose = verbose
        self._actual_threshold = actual_threshold
        self._check_count = 0

        if self.verbose:
            self.observer.trace(f"[{self.name}] Initialized SimPfcXoffExecutor with threshold={actual_threshold}")

    def prepare(self, src_port: int, dst_port: int) -> None:
        """
        Prepare executor for probing (mock implementation).

        In physical executor, this would:
        - Hold buffer (disable TX)
        - Establish base PFC counter

        In mock, this is a no-op.

        Args:
            src_port: Source port ID
            dst_port: Destination port ID
        """
        if self.verbose:
            self.observer.trace(f"[{self.name}] Prepare: src_port={src_port}, dst_port={dst_port}")

    def check(self, src_port: int, dst_port: int, value: int, attempts: int = 1,
              drain_buffer: bool = True, iteration: int = 0, **traffic_keys):
        """
            dst_port: Destination port (unused in mock)
            value: Threshold value to test
            attempts: Number of verification attempts (default 1)
            drain_buffer: Whether to drain buffer (unused in mock)
            iteration: Iteration number (unused in mock)
            **traffic_keys: Traffic keys (unused in mock)

        Returns:
            Tuple[bool, bool]: (success, detected)
                - success: Always True for Normal sim (no hardware failures)
                - detected: True if PFC triggered at this threshold
        """
        self._check_count += 1
        result = value >= self._actual_threshold

        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Check #{self._check_count}: "
                f"value={value}, actual={self._actual_threshold}, pfc_triggered={result}"
            )

        return (True, result)

    def cleanup(self):
        """Cleanup executor resources (mock implementation)."""
        if self.verbose:
            self.observer.trace(f"[{self.name}] Cleanup: total_checks={self._check_count}")


@ExecutorRegistry.register(probe_type='pfc_xoff', executor_env='sim', scenario='noisy')
class SimPfcXoffProbingExecutorNoisy(SimPfcXoffProbingExecutor):
    """
    Noisy sim executor - simulates PFC hardware with random fluctuation.

    Use case:
    - Test algorithm robustness against hardware noise
    - Validate retry logic
    - Test precision degradation under noise
    """

    def __init__(self, observer, name, noise_level=10, **kwargs):
        """
        Initialize noisy sim executor.

        Args:
            noise_level: Random noise range (±noise_level packets)
            **kwargs: Passed to parent SimPfcXoffExecutor
        """
        super().__init__(observer, name, **kwargs)
        self.noise_level = noise_level

        if self.verbose:
            self.observer.trace(f"[{self.name}] Noisy mode: noise_level=±{noise_level}")

    def check(self, src_port: int, dst_port: int, value: int, attempts: int = 1,
              drain_buffer: bool = True, iteration: int = 0, **traffic_keys):
        """Noisy scenario: add random noise to threshold."""
        self._check_count += 1

        # Add random noise to threshold
        noise = random.randint(-self.noise_level, self.noise_level)
        noisy_value = value + noise
        result = noisy_value >= self._actual_threshold

        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Check #{self._check_count}: "
                f"value={value}, noise={noise:+d}, "
                f"noisy={noisy_value}, actual={self._actual_threshold}, pfc_triggered={result}"
            )

        return (True, result)


@ExecutorRegistry.register(probe_type='pfc_xoff', executor_env='sim', scenario='wrong_config')
class SimPfcXoffProbingExecutorWrongConfig(SimPfcXoffProbingExecutor):
    """
    Wrong config sim executor - simulates incorrect PFC threshold configuration.

    Use case:
    - Test algorithm behavior with misconfigured system
    - Validate error detection logic
    - Test threshold offset scenarios
    """

    def __init__(self, observer, name, offset=100, **kwargs):
        """
        Initialize wrong config sim executor.

        Args:
            offset: Threshold offset (packets) - positive = harder to trigger
            **kwargs: Passed to parent SimPfcXoffExecutor
        """
        super().__init__(observer, name, **kwargs)
        self.offset = offset

        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Wrong config mode: offset={offset:+d} "
                f"(effective_threshold={self._actual_threshold + offset})"
            )

    def check(self, src_port: int, dst_port: int, value: int, attempts: int = 1,
              drain_buffer: bool = True, iteration: int = 0, **traffic_keys):
        """Wrong config scenario: apply threshold offset."""
        self._check_count += 1

        # Apply offset to actual threshold (simulates wrong config)
        effective_threshold = self._actual_threshold + self.offset
        result = value >= effective_threshold

        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Check #{self._check_count}: "
                f"value={value}, offset={self.offset:+d}, "
                f"effective={effective_threshold}, pfc_triggered={result}"
            )

        return (True, result)


@ExecutorRegistry.register(probe_type='pfc_xoff', executor_env='sim', scenario='intermittent')
class SimPfcXoffProbingExecutorIntermittent(SimPfcXoffProbingExecutor):
    """
    Intermittent failure sim executor - simulates random PFC hardware failures.

    Use case:
    - Test retry logic
    - Validate error handling
    - Test algorithm resilience to transient errors
    """

    def __init__(self, observer, name, failure_rate=0.1, **kwargs):
        """
        Initialize intermittent failure sim executor.

        Args:
            failure_rate: Probability of failure (0.0-1.0)
            **kwargs: Passed to parent SimPfcXoffExecutor
        """
        super().__init__(observer, name, **kwargs)
        self.failure_rate = failure_rate
        self.failure_count = 0

        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Intermittent failure mode: "
                f"failure_rate={failure_rate*100:.1f}%"
            )

    def check(self, src_port: int, dst_port: int, value: int, attempts: int = 1,
              drain_buffer: bool = True, iteration: int = 0, **traffic_keys):
        """Intermittent scenario: random failures."""
        self._check_count += 1

        # Random failure simulation
        if random.random() < self.failure_rate:
            self.failure_count += 1
            error_msg = f"PFC hardware failure #{self.failure_count} (simulated)"

            if self.verbose:
                self.observer.trace(
                    f"[{self.name}] Check #{self._check_count}: FAILED - {error_msg}"
                )

            raise Exception(error_msg)

        # Normal check if no failure
        result = value >= self._actual_threshold

        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Check #{self._check_count}: "
                f"value={value}, actual={self._actual_threshold}, pfc_triggered={result}"
            )

        return (True, result)
