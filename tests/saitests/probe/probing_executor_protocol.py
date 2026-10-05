"""
Probing Executor Protocol - Unified Interface

Defines the standard interface that all threshold probing executors must implement.
This protocol enables algorithm code to be completely executor-agnostic.

Design Philosophy:
- Define common interface without implementation
- Enable algorithm reuse across different probing types (PFC Xoff, Ingress Drop, etc.)
- Support both physical device and mock executors
- Type-safe with Python's Protocol (structural subtyping)

Usage:
    def my_algorithm(executor: ProbingExecutorProtocol):
        executor.prepare(src, dst)
        success, detected = executor.check(src, dst, value)
        # Works with ANY executor implementing this protocol
"""

from typing import Protocol, Tuple, runtime_checkable


@runtime_checkable
class ProbingExecutorProtocol(Protocol):
    """
    Protocol defining the standard executor interface for threshold probing

    All probing executors (PfcxoffProbingExecutor, IngressDropProbingExecutor, etc.)
    must implement these methods to be compatible with unified algorithms.

    This is a structural protocol - classes don't need to explicitly inherit from it.
    If a class has these methods with matching signatures, it automatically satisfies
    the protocol.
    """

    def prepare(self, src_port: int, dst_port: int) -> None:
        """
        Prepare ports for threshold detection

        Ensures clean buffer state before probing begins.
        Typically involves draining buffers and setting up congestion conditions.

        Args:
            src_port: Source port for traffic generation
            dst_port: Destination port for threshold detection
        """
        ...

    def check(self, src_port: int, dst_port: int, value: int,
              attempts: int = 1, drain_buffer: bool = True,
              iteration: int = 0, **traffic_keys) -> Tuple[bool, bool]:
        """
        Check if threshold is reached at given value

        Standard 5-step verification process:
        1. Port preparation (optional via drain_buffer)
        2. Baseline measurement
        3. Traffic injection
        4. Wait for counter refresh
        5. Threshold detection

        Args:
            src_port: Source port for traffic generation
            dst_port: Destination port for threshold detection
            value: Packet count to test
            attempts: Number of verification attempts for consistency
            drain_buffer: Whether to drain buffer before testing
            iteration: Current iteration number (for metrics tracking)
            **traffic_keys: Traffic identification keys (e.g., pg=3, queue=5)

        Returns:
            Tuple[success, detected]:
                - success: True if verification completed without errors
                - detected: True if threshold was triggered at this value
        """
        ...
