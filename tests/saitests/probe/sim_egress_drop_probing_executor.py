#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sim Egress Drop Executors - Simulated hardware behavior for testing

Provides multiple sim executor implementations for different test scenarios:
- SimEgressDropExecutor: Normal sim executor
- SimEgressDropExecutorNoisy: Simulates hardware with random noise
- SimEgressDropExecutorWrongConfig: Simulates wrong threshold configuration
- SimEgressDropExecutorIntermittent: Simulates intermittent hardware failures
- SimEgressDropExecutorBadSpot: Simulates deterministic failures at specific values

Architecture: Mirrors sim_ingress_drop_probing_executor.py for consistency.

Usage:
    # Normal sim
    executor = ExecutorRegistry.create('egress_drop', 'sim',
                                       observer=obs, name='queue3')

    # Noisy sim
    executor = ExecutorRegistry.create('egress_drop', 'sim',
                                       scenario='noisy', noise_level=10,
                                       observer=obs, name='queue3')
"""

import random
from executor_registry import ExecutorRegistry


@ExecutorRegistry.register(probe_type='egress_drop', executor_env='sim')
class SimEgressDropProbingExecutor:
    """
    Normal sim executor for egress drop detection.

    Simulates ideal hardware behavior:
    - Deterministic drop detection
    - No noise or errors
    - Predictable threshold behavior
    """

    def __init__(self, observer, name, ptftest=None, verbose=True, actual_threshold=500, **kwargs):
        """
        Initialize mock egress drop executor.

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
            self.observer.trace(f"[{self.name}] Initialized SimEgressDropExecutor with threshold={actual_threshold}")

    def prepare(self, src_port: int, dst_port: int) -> None:
        """Prepare executor for probing (mock: no-op)."""
        if self.verbose:
            self.observer.trace(f"[{self.name}] Prepare: src_port={src_port}, dst_port={dst_port}")

    def check(self, src_port: int, dst_port: int, value: int, attempts: int = 1,
              drain_buffer: bool = True, iteration: int = 0, **traffic_keys):
        """
        Normal scenario: simple threshold comparison.

        Returns:
            Tuple[bool, bool]: (success=True, detected=value>=threshold)
        """
        self._check_count += 1
        result = value >= self._actual_threshold

        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Check #{self._check_count}: "
                f"value={value}, actual={self._actual_threshold}, drop={result}"
            )

        return (True, result)

    def cleanup(self):
        """Cleanup executor resources (mock implementation)."""
        if self.verbose:
            self.observer.trace(f"[{self.name}] Cleanup: total_checks={self._check_count}")


@ExecutorRegistry.register(probe_type='egress_drop', executor_env='sim', scenario='noisy')
class SimEgressDropProbingExecutorNoisy(SimEgressDropProbingExecutor):
    """Noisy sim executor - simulates hardware with random fluctuation."""

    def __init__(self, observer, name, noise_level=10, **kwargs):
        super().__init__(observer, name, **kwargs)
        self.noise_level = noise_level
        if self.verbose:
            self.observer.trace(f"[{self.name}] Noisy mode: noise_level=±{noise_level}")

    def check(self, src_port: int, dst_port: int, value: int, attempts: int = 1,
              drain_buffer: bool = True, iteration: int = 0, **traffic_keys):
        """Noisy scenario: add random noise to threshold."""
        self._check_count += 1
        noise = random.randint(-self.noise_level, self.noise_level)
        noisy_value = value + noise
        result = noisy_value >= self._actual_threshold
        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Check #{self._check_count}: "
                f"value={value}, noise={noise:+d}, noisy={noisy_value}, "
                f"actual={self._actual_threshold}, drop={result}"
            )
        return (True, result)


@ExecutorRegistry.register(probe_type='egress_drop', executor_env='sim', scenario='wrong_config')
class SimEgressDropProbingExecutorWrongConfig(SimEgressDropProbingExecutor):
    """Wrong config sim executor - simulates incorrect threshold configuration."""

    def __init__(self, observer, name, offset=100, **kwargs):
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
        effective_threshold = self._actual_threshold + self.offset
        result = value >= effective_threshold
        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Check #{self._check_count}: "
                f"value={value}, offset={self.offset:+d}, "
                f"effective={effective_threshold}, drop={result}"
            )
        return (True, result)


@ExecutorRegistry.register(probe_type='egress_drop', executor_env='sim', scenario='intermittent')
class SimEgressDropProbingExecutorIntermittent(SimEgressDropProbingExecutor):
    """Intermittent failure sim executor - simulates random hardware failures."""

    def __init__(self, observer, name, failure_rate=0.1, **kwargs):
        super().__init__(observer, name, **kwargs)
        self.failure_rate = failure_rate
        self.failure_count = 0
        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Intermittent failure mode: failure_rate={failure_rate*100:.1f}%"
            )

    def check(self, src_port: int, dst_port: int, value: int, attempts: int = 1,
              drain_buffer: bool = True, iteration: int = 0, **traffic_keys):
        """Intermittent scenario: random failures."""
        self._check_count += 1
        if random.random() < self.failure_rate:
            self.failure_count += 1
            if self.verbose:
                self.observer.trace(
                    f"[{self.name}] Check #{self._check_count}: "
                    f"FAILED - Hardware failure #{self.failure_count} (simulated)"
                )
            return (False, False)
        result = value >= self._actual_threshold
        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Check #{self._check_count}: "
                f"value={value}, actual={self._actual_threshold}, drop={result}"
            )
        return (True, result)


@ExecutorRegistry.register(probe_type='egress_drop', executor_env='sim', scenario='bad_spot')
class SimEgressDropProbingExecutorBadSpot(SimEgressDropProbingExecutor):
    """Bad-spot sim executor — simulates hardware that always fails at specific values."""

    def __init__(self, observer, name, bad_values=None, **kwargs):
        super().__init__(observer, name, **kwargs)
        self.bad_values = set(bad_values or [])
        self.bad_hit_count = 0
        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Bad-spot mode: bad_values={sorted(self.bad_values)}"
            )

    def check(self, src_port: int, dst_port: int, value: int, attempts: int = 1,
              drain_buffer: bool = True, iteration: int = 0, **traffic_keys):
        """Bad-spot scenario: always fail at specific values."""
        self._check_count += 1
        if value in self.bad_values:
            self.bad_hit_count += 1
            if self.verbose:
                self.observer.trace(
                    f"[{self.name}] Check #{self._check_count}: "
                    f"value={value} HIT BAD SPOT (hit #{self.bad_hit_count})"
                )
            return (False, False)
        result = value >= self._actual_threshold
        if self.verbose:
            self.observer.trace(
                f"[{self.name}] Check #{self._check_count}: "
                f"value={value}, actual={self._actual_threshold}, drop={result}"
            )
        return (True, result)
