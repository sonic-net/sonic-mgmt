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

    def sai_thrift_read_port_counters(client, asic_type, port):
        return [0] * 20, [0] * 10

    port_list = {"src": {}}


def _get_fill_leakout_plus_one():
    """
    Lazy import of fill_leakout_plus_one at call time.

    Module-load-time imports failed silently in some deployments (probably a
    sys.path ordering issue between the probe/ and py3/ directories). By the
    time an executor's check() runs, the probing test module has already
    imported sai_qos_tests successfully, so this lookup is reliable.

    Returns the function on success, or None with the real exception written
    to stderr on failure (so we can diagnose instead of silently no-op'ing).
    """
    try:
        from sai_qos_tests import fill_leakout_plus_one as _fn
        return _fn
    except Exception as e:  # noqa: BLE001 — we want to see the actual error
        sys.stderr.write(
            f"[PFC Xoff Executor] lazy import of fill_leakout_plus_one failed: "
            f"{type(e).__name__}: {e}\n")
        return None


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

                # ===== Step 1.5: Leakout compensation (cisco-8000) =====
                # Mirror PfcStdTest's compensation stack for cisco-8000:
                #   1. fill_leakout_plus_one() primes the queue with ~1 cell (dynamic
                #      "initial burst" leakout).
                #   2. Add pkts_num_leak_out (static per-platform value from qos.yaml)
                #      to compensate for the ongoing trickle-out during the burst.
                # Net effect: after send, buffer occupancy ~= `value` cells.
                # Use substring match to cover variants like 'cisco-8000-gr2'.
                # Skipped for incremental (drain_buffer=False) sends since the buffer
                # is already primed from a prior drained iteration.
                send_count = value
                asic_type = getattr(self.ptftest, 'asic_type', '') or ''
                fill_leakout_fn = _get_fill_leakout_plus_one()
                if (drain_buffer and value > 0
                        and 'cisco-8000' in asic_type
                        and fill_leakout_fn is not None):
                    pkt = self.ptftest.stream_mgr.get_packet(
                        src_port, dst_port, **traffic_keys)
                    if pkt is not None:
                        pkts_num_leak_out = int(getattr(self.ptftest, 'pkts_num_leak_out', 0) or 0)
                        fill_leakout_fn(
                            self.ptftest, src_port, dst_port, pkt,
                            traffic_keys.get('pg', 0), asic_type)
                        # Compensation math:
                        #   -1  : fill_leakout_plus_one primed the queue with 1 cell
                        #   +pkts_num_leak_out : ongoing leakout absorbs this many
                        #                        cells during the burst
                        send_count = max(0, value + pkts_num_leak_out - 1)

                # ===== Step 2: Baseline measurement =====
                sport_cnt_base, _ = sai_thrift_read_port_counters(
                    self.ptftest.src_client,
                    self.ptftest.asic_type,
                    port_list["src"][src_port]
                )

                # ===== Step 3: Traffic injection =====
                if send_count > 0:
                    self.ptftest.buffer_ctrl.send_traffic(src_port, dst_port, send_count, **traffic_keys)

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
                        f"send_count={send_count}, pfc_triggered={pfc_triggered}")

            # Result analysis based on attempts
            return_result = (True, results[0])
            # Multiple attempts: check consistency (set dedup detects mixed True/False)
            if len(results) > 1 and len(set(results)) > 1:
                return_result = (False, False)

            if self.verbose and self.observer:
                self.observer.trace(
                    f"[PFC Xoff Executor] Check complete: value={value}, attempts={attempts}, "
                    f"results={results}, final_detected={return_result[1]}, success={return_result[0]}")

            return return_result

        except Exception as e:
            if self.verbose and self.observer:
                self.observer.trace(f"[PFC Xoff Executor] Check failed: value={value}, error={e}")
            return False, False
