"""
Unified PFC Xoff Probing Executor - All Phases

This module provides a unified executor for all PFC Xoff threshold probing phases.
Eliminates code duplication and ensures consistent behavior across all phases.

Key Design Principles:
1. Single implementation for Phase 1/2/3/4
2. Generic naming (no phase-specific references)
3. Configurable verification attempts
4. Consistent 5-step detection process
5. Both physical device and UT/Mock support

Benefits:
- Bug fixes only need to be applied once
- API consistency guaranteed across all phases
- Easier maintenance and testing
- Reduced code complexity

Usage:
    # Physical device (via ExecutorRegistry)
    executor = ExecutorRegistry.create('pfc_xoff', 'physical', ptftest=self, ...)

    # Mock (via ExecutorRegistry)
    executor = ExecutorRegistry.create('pfc_xoff', 'mock', simulated_threshold=13660, ...)
"""

import sys
import time
from typing import Tuple

from executor_registry import ExecutorRegistry

try:
    from switch import (
        sai_thrift_read_port_counters,
        port_list
    )
    # Import constants from sai_qos_tests.py
    import os
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.join(parent_dir, 'py3'))
    try:
        from sai_qos_tests import PORT_TX_CTRL_DELAY, PFC_TRIGGER_DELAY
    except ImportError:
        PORT_TX_CTRL_DELAY = 2
        PFC_TRIGGER_DELAY = 2
except ImportError:
    # Mock for testing environments
    PORT_TX_CTRL_DELAY = 2
    PFC_TRIGGER_DELAY = 2

    def sai_thrift_read_port_counters(*args):
        return [0] * 20, [0] * 10

    port_list = {"src": {}}


@ExecutorRegistry.register(probe_type='pfc_xoff', executor_env='physical')
class PfcXoffProbingExecutor:
    """
    Unified PFC Xoff Probing Executor for All Phases

    Generic executor that can be used by any phase (1/2/3/4).
    Provides consistent PFC Xoff threshold detection logic with:
    - 5-step verification process
    - Configurable verification attempts
    - Result consistency checking
    - Performance statistics tracking per phase
    """

    def __init__(self, ptftest, observer=None, verbose: bool = False, name: str = ""):
        """
        Initialize unified PFC Xoff executor

        Args:
            ptftest: PTF test instance providing hardware access methods
            observer: Observer instance for logging (optional, for log output)
            verbose: Enable debug output for executor operations
            name: Optional name to identify this executor instance (e.g., "upper_bound", "lower_bound")
        """

        self.ptftest = ptftest
        self.observer = observer
        self.verbose = verbose
        self.name = name

    def prepare(self, src_port: int, dst_port: int) -> None:
        """
        Port preparation for PFC Xoff threshold detection

        Ensures clean buffer state before threshold probing begins.
        """
        # Standard preparation cycle using buffer_ctrl
        self.ptftest.buffer_ctrl.drain_buffer([dst_port])
        time.sleep(PORT_TX_CTRL_DELAY)
        self.ptftest.buffer_ctrl.hold_buffer([dst_port])
        time.sleep(PORT_TX_CTRL_DELAY)

        if self.verbose and self.observer:
            self.observer.trace(f"[PFC Xoff Executor] Prepare: src={src_port}, dst={dst_port}")

    def check(self, src_port: int, dst_port: int, value: int, attempts: int = 1,
              drain_buffer: bool = True, iteration: int = 0, **traffic_keys) -> Tuple[bool, bool]:
        """
        PFC Xoff threshold check with configurable verification attempts

        Standard 5-step verification process:
        1. Port preparation - ensure clean buffer state (optional via drain_buffer)
        2. Baseline measurement - read PFC counter before traffic
        3. Traffic injection - send packets to trigger threshold
        4. Wait for counter refresh - allow hardware to update
        5. PFC Xoff detection - compare counter after traffic

        Args:
            src_port: Source port for traffic generation
            dst_port: Destination port for PFC Xoff detection
            value: Packet count to test
                   - When drain_buffer=True: total packet count (buffer drained before sending)
                   - When drain_buffer=False: incremental packet count (added to existing buffer)
            attempts: Number of verification attempts (default 1)
            drain_buffer: Whether to drain buffer before sending (default True)
                         - True: enable/disable tx to drain buffer, then send 'value' packets
                         - False: skip buffer draining, send 'value' packets incrementally
            iteration: Current iteration number (for observer metrics tracking, default 0)
            **traffic_keys: Traffic identification keys (e.g., pg=3, queue=5)

        Returns:
            Tuple[success, detected]:
                - success: True if verification completed without errors
                - detected: True if PFC Xoff was triggered at this value
        """
        # Step3.3.6: Require observer for fine-grained timing measurement
        assert self.observer is not None, "Observer is required for Step3.3.6 fine-grained timing"

        try:
            results = []

            # ===== Step3.3.6: Loop attempts times =====
            for attempt in range(attempts):
                # ===== Step 1: Port preparation - ensure clean buffer state (optional) =====
                if drain_buffer:
                    self.ptftest.buffer_ctrl.drain_buffer([dst_port])  # Drain existing buffer content
                    time.sleep(PORT_TX_CTRL_DELAY)
                    self.ptftest.buffer_ctrl.hold_buffer([dst_port])     # Simulate congestion condition
                    time.sleep(PORT_TX_CTRL_DELAY)

                # ===== Step 2: Baseline measurement =====
                sport_cnt_base, _ = sai_thrift_read_port_counters(
                    self.ptftest.src_client,
                    self.ptftest.asic_type,
                    port_list["src"][src_port]
                )

                # ===== Step 3: Traffic injection =====
                if value > 0:
                    self.ptftest.buffer_ctrl.send_traffic(src_port, dst_port, value, **traffic_keys)

                # ===== Step 4: Wait for counter refresh =====
                time.sleep(PFC_TRIGGER_DELAY)

                # ===== Step 5: PFC Xoff detection =====
                sport_cnt_curr, _ = sai_thrift_read_port_counters(
                    self.ptftest.src_client,
                    self.ptftest.asic_type,
                    port_list["src"][src_port]
                )
                # Check if PFC Xoff was triggered
                pfc_triggered = sport_cnt_curr[self.ptftest.cnt_pg_idx] > sport_cnt_base[self.ptftest.cnt_pg_idx]
                results.append(pfc_triggered)

                if self.verbose and self.observer:
                    self.observer.trace(
                        f"[PFC Xoff Executor] Verification {attempt + 1}/{attempts}: "
                        f"src={src_port}, dst={dst_port}, value={value}, "
                        f"pfc_triggered={pfc_triggered}")

            # Result analysis based on attempts
            if attempts == 1:
                # Single attempt: direct result
                detected = results[0]
                success = True
            else:
                # Multiple attempts: require consistent results for reliable detection
                all_true = all(results)
                all_false = not any(results)
                all_equal = all_true or all_false

                if all_equal:
                    # Verification successful - consistent results
                    detected = results[0]  # Any result since they're all the same
                    success = True
                else:
                    # Verification failed - inconsistent results indicate noise/error
                    detected = False
                    success = False

            if self.verbose and self.observer:
                self.observer.trace(
                    f"[PFC Xoff Executor] Check complete: value={value}, attempts={attempts}, "
                    f"results={results}, final_detected={detected}, success={success}")

            return success, detected

        except Exception as e:
            if self.verbose and self.observer:
                self.observer.trace(f"[PFC Xoff Executor] Check failed: value={value}, error={e}")
            return False, False
