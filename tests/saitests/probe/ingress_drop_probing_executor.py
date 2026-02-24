"""
Unified Ingress Drop Probing Executor - All Phases

This module provides a unified executor for all Ingress Drop threshold probing phases.
Eliminates code duplication and ensures consistent behavior across all phases.

Key Design Principles:
1. Single implementation for Phase 1/2/3
2. Generic naming (no phase-specific references)
3. Configurable verification attempts
4. Consistent 5-step detection process
5. Both physical device and UT/Mock support

Benefits:
- Bug fixes only need to be applied once
- API consistency guaranteed across all phases
- Easier maintenance and testing
- Reduced code complexity

Architecture Pattern:
- Mirrors PfcXoffProbingExecutor design
- Adapted for Ingress Drop detection logic
- Uses INGRESS_DROP and INGRESS_PORT_BUFFER_DROP counters

Usage:
    # Physical device (via ExecutorRegistry)
    executor = ExecutorRegistry.create('ingress_drop', 'physical', ptftest=self, ...)

    # Mock (via ExecutorRegistry)
    executor = ExecutorRegistry.create('ingress_drop', 'mock', simulated_threshold=13660, ...)
"""

import sys
import time
from typing import Tuple

from executor_registry import ExecutorRegistry

try:
    from switch import (
        sai_thrift_read_port_counters,
        sai_thrift_read_pg_drop_counters,
        port_list
    )
    # Import constants from sai_qos_tests.py
    import os
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, os.path.join(parent_dir, 'py3'))
    try:
        from sai_qos_tests import PORT_TX_CTRL_DELAY, PFC_TRIGGER_DELAY, INGRESS_DROP, INGRESS_PORT_BUFFER_DROP
    except ImportError:
        PORT_TX_CTRL_DELAY = 2
        PFC_TRIGGER_DELAY = 2
        INGRESS_DROP = 1
        INGRESS_PORT_BUFFER_DROP = 12
except ImportError:
    # Mock for testing environments
    PORT_TX_CTRL_DELAY = 2
    PFC_TRIGGER_DELAY = 2
    INGRESS_DROP = 1
    INGRESS_PORT_BUFFER_DROP = 12

    def sai_thrift_read_port_counters(*args):
        return [0] * 20, [0] * 10

    def sai_thrift_read_pg_drop_counters(*args):
        return [0] * 8

    port_list = {"src": {}}


@ExecutorRegistry.register(probe_type='ingress_drop', executor_env='physical')
class IngressDropProbingExecutor:
    """
    Unified Ingress Drop Probing Executor for All Phases

    Generic executor that can be used by any phase (1/2/3).
    Provides consistent Ingress Drop threshold detection logic with:
    - 5-step verification process
    - Configurable verification attempts
    - Result consistency checking
    - Performance statistics tracking per phase

    Design Pattern:
    - Mirrors PfcxoffProbingExecutor.py
    - Adapted for Ingress Drop detection counters
    - Uses INGRESS_DROP and INGRESS_PORT_BUFFER_DROP
    """

    def __init__(self, ptftest, observer=None, verbose: bool = False,
                 name: str = "", use_pg_drop_counter: bool = False):
        """
        Initialize unified Ingress Drop executor

        Args:
            ptftest: PTF test instance providing hardware access methods
            observer: Observer instance for logging (optional, for log output)
            verbose: Enable debug output for executor operations
            name: Optional name to identify this executor instance (e.g., "upper_bound", "lower_bound")
            use_pg_drop_counter: Use PG drop counter (True) or Port ingress drop counter (False)
                                 Default: False (Solution 2 - Port counter with margin, compatible with Broadcom)
                                 Can be overridden by environment variable INGRESS_DROP_USE_PG_COUNTER
        """
        self.ptftest = ptftest
        self.observer = observer
        self.verbose = verbose
        self.name = name

        # Use counter strategy from parameter (set by ProbingBase.setUp() from env var)
        self.use_pg_drop_counter = use_pg_drop_counter

        if self.verbose and self.observer:
            strategy = "PG drop counter" if self.use_pg_drop_counter else "Port ingress drop counter"
            self.observer.trace(f"[Ingress Drop Executor] Using {strategy}")

    def prepare(self, src_port: int, dst_port: int) -> None:
        """
        Port preparation for Ingress Drop threshold detection

        Ensures clean buffer state before threshold probing begins.
        """
        # Standard preparation cycle using buffer_ctrl
        self.ptftest.buffer_ctrl.drain_buffer([dst_port])
        time.sleep(PORT_TX_CTRL_DELAY)
        self.ptftest.buffer_ctrl.hold_buffer([dst_port])
        time.sleep(PORT_TX_CTRL_DELAY)

        if self.verbose and self.observer:
            self.observer.trace(f"[Ingress Drop Executor] Prepare: src={src_port}, dst={dst_port}")

    def check(self, src_port: int, dst_port: int, value: int, attempts: int = 1,
              drain_buffer: bool = True, iteration: int = 0, **traffic_keys) -> Tuple[bool, bool]:
        """
        Ingress Drop threshold check with configurable verification attempts

        Standard 5-step verification process:
        1. Port preparation - ensure clean buffer state (optional via drain_buffer)
        2. Baseline measurement - read Ingress Drop counter before traffic
        3. Traffic injection - send packets to trigger threshold
        4. Wait for counter refresh - allow hardware to update
        5. Ingress Drop detection - compare counter after traffic

        Args:
            src_port: Source port for traffic generation
            dst_port: Destination port for Ingress Drop detection
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
                - detected: True if Ingress Drop was triggered at this value
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
                if self.use_pg_drop_counter:
                    # Solution 1: Use PG drop counter (supports multi-PG per port)
                    pg_drop_base = sai_thrift_read_pg_drop_counters(
                        self.ptftest.src_client,
                        port_list["src"][src_port]
                    )
                    if self.verbose and self.observer:
                        # Get actual PG number: from traffic_keys or reverse-calculate from cnt_pg_idx
                        # cnt_pg_idx = pg + 2 (for PFC counter offset), so pg = cnt_pg_idx - 2
                        pg_num = traffic_keys.get('pg') if traffic_keys else (self.ptftest.cnt_pg_idx - 2)
                        self.observer.trace(
                            f"[Ingress Drop] Step2-Baseline: Using PG drop counter, "
                            f"PG{pg_num} baseline={pg_drop_base[pg_num]}, all_pgs={pg_drop_base}"
                        )
                else:
                    # Solution 2: Use Port ingress drop counter (requires margin in persist)
                    sport_cnt_base, _ = sai_thrift_read_port_counters(
                        self.ptftest.src_client,
                        self.ptftest.asic_type,
                        port_list["src"][src_port]
                    )
                    if self.verbose and self.observer:
                        self.observer.trace(
                            f"[Ingress Drop] Step2-Baseline: Using Port counter, "
                            f"INGRESS_DROP={sport_cnt_base[INGRESS_DROP]}, "
                            f"INGRESS_PORT_BUFFER_DROP={sport_cnt_base[INGRESS_PORT_BUFFER_DROP]}"
                        )

                # ===== Step 3: Traffic injection =====
                # Convert algorithm value to traffic amount (64-byte packets, 1 packet = 1 cell)
                if value > 0:
                    self.ptftest.buffer_ctrl.send_traffic(src_port, dst_port, value, **traffic_keys)

                # ===== Step 4: Wait for counter refresh =====
                time.sleep(PFC_TRIGGER_DELAY)

                # ===== Step 5: Ingress Drop detection =====
                if self.use_pg_drop_counter:
                    # Solution 1: PG-level drop counter (multi-PG safe)
                    pg_drop_curr = sai_thrift_read_pg_drop_counters(
                        self.ptftest.src_client,
                        port_list["src"][src_port]
                    )
                    # Get actual PG number: from traffic_keys or reverse-calculate from cnt_pg_idx
                    # cnt_pg_idx = pg + 2 (for PFC counter offset), so pg = cnt_pg_idx - 2
                    pg_num = traffic_keys.get('pg') if traffic_keys else (self.ptftest.cnt_pg_idx - 2)
                    ingress_drop_triggered = pg_drop_curr[pg_num] > pg_drop_base[pg_num]

                    if self.verbose and self.observer:
                        drop_diff = pg_drop_curr[pg_num] - pg_drop_base[pg_num]
                        self.observer.trace(
                            f"[Ingress Drop] Step5-Detection: PG{pg_num} drop counter: "
                            f"base={pg_drop_base[pg_num]}, curr={pg_drop_curr[pg_num]}, "
                            f"diff={drop_diff}, triggered={ingress_drop_triggered}"
                        )
                        # Log all PGs for multi-PG debugging
                        all_diffs = [pg_drop_curr[i] - pg_drop_base[i] for i in range(len(pg_drop_curr))]
                        if any(d != 0 for d in all_diffs):
                            self.observer.trace(
                                f"[Ingress Drop] All PG drop changes: {all_diffs}"
                            )
                else:
                    # Solution 2: Port-level ingress drop counter (affected by all PGs)
                    sport_cnt_curr, _ = sai_thrift_read_port_counters(
                        self.ptftest.src_client,
                        self.ptftest.asic_type,
                        port_list["src"][src_port]
                    )
                    ingress_drop_triggered = (
                        sport_cnt_curr[INGRESS_DROP] > sport_cnt_base[INGRESS_DROP] or
                        sport_cnt_curr[INGRESS_PORT_BUFFER_DROP] > sport_cnt_base[INGRESS_PORT_BUFFER_DROP]
                    )

                    if self.verbose and self.observer:
                        ing_drop_diff = sport_cnt_curr[INGRESS_DROP] - sport_cnt_base[INGRESS_DROP]
                        ing_buf_drop_diff = (sport_cnt_curr[INGRESS_PORT_BUFFER_DROP] -
                                             sport_cnt_base[INGRESS_PORT_BUFFER_DROP])
                        self.observer.trace(
                            f"[Ingress Drop] Step5-Detection: Port counter: "
                            f"INGRESS_DROP: base={sport_cnt_base[INGRESS_DROP]}, "
                            f"curr={sport_cnt_curr[INGRESS_DROP]}, diff={ing_drop_diff}, "
                            f"INGRESS_PORT_BUFFER_DROP: base={sport_cnt_base[INGRESS_PORT_BUFFER_DROP]}, "
                            f"curr={sport_cnt_curr[INGRESS_PORT_BUFFER_DROP]}, "
                            f"diff={ing_buf_drop_diff}, triggered={ingress_drop_triggered}"
                        )

                results.append(ingress_drop_triggered)

                if self.verbose and self.observer:
                    strategy = "PG drop counter" if self.use_pg_drop_counter else "Port counter"
                    self.observer.trace(
                        f"[Ingress Drop] Verification {attempt + 1}/{attempts}: "
                        f"strategy={strategy}, src={src_port}, dst={dst_port}, value={value}, "
                        f"triggered={ingress_drop_triggered}"
                    )

            # ===== Result analysis based on attempts =====
            return_result = (True, results[0])
            # Multiple attempts: check consistency
            # Inconsistent results indicate noise/error
            if len(results) > 1 and len(set(results)) > 1:
                return_result = (False, False)

            # Single attempt or consistent multiple attempts
            if self.verbose:
                self.observer.trace(
                    f"[Ingress Drop Executor] Check complete: value={value}, attempts={attempts}, "
                    f"results={results}, final_detected={return_result[1]}, success={return_result[0]}"
                )

            return return_result

        except Exception as e:
            if self.verbose:
                self.observer.trace(f"[Ingress Drop Executor] Check error: {e}")
            return False, False
