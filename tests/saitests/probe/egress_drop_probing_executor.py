"""
Unified Egress Drop Probing Executor - All Phases

This module provides a unified executor for all Egress Drop threshold probing phases.

Key Design Principles:
1. Single implementation for Phase 1/2/3
2. Generic naming (no phase-specific references)
3. Configurable verification attempts
4. Consistent 5-step detection process
5. Both physical device and UT/Mock support

Architecture Pattern:
- Mirrors IngressDropProbingExecutor design
- Adapted for Egress Drop detection logic
- Uses EGRESS_DROP and EGRESS_PORT_BUFFER_DROP counters on dst port

Key Differences from IngressDrop:
- Counter location: dst port (egress side) vs src port (ingress side)
- Thrift client: dst_client vs src_client
- Port list: port_list['dst'] vs port_list['src']
- Counter indices: EGRESS_DROP=0, EGRESS_PORT_BUFFER_DROP=13

Reference: Legacy LossyQueueTest in sai_qos_tests.py

Usage:
    # Physical device (via ExecutorRegistry)
    executor = ExecutorRegistry.create('egress_drop', 'physical', ptftest=self, ...)

    # Mock (via ExecutorRegistry)
    executor = ExecutorRegistry.create('egress_drop', 'sim', actual_threshold=1000, ...)
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
        from sai_qos_tests import PORT_TX_CTRL_DELAY, PFC_TRIGGER_DELAY, EGRESS_DROP, EGRESS_PORT_BUFFER_DROP
    except ImportError:
        PORT_TX_CTRL_DELAY = 2
        PFC_TRIGGER_DELAY = 2
        EGRESS_DROP = 0
        EGRESS_PORT_BUFFER_DROP = 13
except ImportError:
    # Mock for testing environments
    PORT_TX_CTRL_DELAY = 2
    PFC_TRIGGER_DELAY = 2
    EGRESS_DROP = 0
    EGRESS_PORT_BUFFER_DROP = 13

    def sai_thrift_read_port_counters(client, asic_type, port):
        return [0] * 20, [0] * 10

    port_list = {"dst": {}}


def _sai_thrift_read_port_counters(*args, **kwargs):
    """Pass-through call to ``sai_thrift_read_port_counters``.

    The repo defines ``sai_thrift_read_port_counters`` twice with
    different arities:

      tests/saitests/switch.py:751      def(client, port)              # legacy py2
      tests/saitests/py3/switch.py:799  def(client, asic_type, port)   # py3, used at runtime

    PTF runs under py3 and resolves to the 3-arg version via
    ``sys.path`` manipulation. CodeQL static analysis binds to the
    2-arg legacy version and produces a ``py/call/wrong-arguments``
    false-positive at every 3-arg call site. The ``*args, **kwargs``
    signature here breaks CodeQL's arity check while preserving
    runtime semantics (positional/keyword args pass through
    transparently). The ``_`` prefix marks this as a localized
    workaround for the same underlying ``sai_thrift_read_port_counters``.
    """
    return sai_thrift_read_port_counters(*args, **kwargs)


@ExecutorRegistry.register(probe_type='egress_drop', executor_env='physical')
class EgressDropProbingExecutor:
    """
    Unified Egress Drop Probing Executor for All Phases

    Generic executor that can be used by any phase (1/2/3).
    Provides consistent Egress Drop threshold detection logic with:
    - 5-step verification process
    - Configurable verification attempts
    - Result consistency checking
    - Performance statistics tracking per phase

    Design Pattern:
    - Mirrors IngressDropProbingExecutor
    - Reads counters from dst port (egress side) via dst_client
    - Uses EGRESS_DROP and EGRESS_PORT_BUFFER_DROP
    """

    def __init__(self, ptftest, observer=None, verbose: bool = False, name: str = ""):
        """
        Initialize unified Egress Drop executor

        Args:
            ptftest: PTF test instance providing hardware access methods
            observer: Observer instance for logging (optional, for log output)
            verbose: Enable debug output for executor operations
            name: Optional name to identify this executor instance
        """
        self.ptftest = ptftest
        self.observer = observer
        self.verbose = verbose
        self.name = name

        if self.verbose and self.observer:
            self.observer.trace("[Egress Drop Executor] Initialized")

    def prepare(self, src_port: int, dst_port: int) -> None:
        """
        Port preparation for Egress Drop threshold detection

        Ensures clean buffer state before threshold probing begins.
        Blocks dst TX to cause egress queue buildup — same mechanism as IngressDrop.
        """
        self.ptftest.buffer_ctrl.drain_buffer([dst_port])
        time.sleep(PORT_TX_CTRL_DELAY)
        self.ptftest.buffer_ctrl.hold_buffer([dst_port])
        time.sleep(PORT_TX_CTRL_DELAY)

        if self.verbose and self.observer:
            self.observer.trace(f"[Egress Drop Executor] Prepare: src={src_port}, dst={dst_port}")

    def check(self, src_port: int, dst_port: int, value: int, attempts: int = 1,
              drain_buffer: bool = True, iteration: int = 0, **traffic_keys) -> Tuple[bool, bool]:
        """
        Egress Drop threshold check with configurable verification attempts

        Standard 5-step verification process:
        1. Port preparation - ensure clean buffer state (optional via drain_buffer)
        2. Baseline measurement - read Egress Drop counter on dst port before traffic
        3. Traffic injection - send packets to trigger threshold
        4. Wait for counter refresh - allow hardware to update
        5. Egress Drop detection - compare counter after traffic on dst port

        Args:
            src_port: Source port for traffic generation
            dst_port: Destination port for Egress Drop detection
            value: Packet count to test
            attempts: Number of verification attempts (default 1)
            drain_buffer: Whether to drain buffer before sending (default True)
            iteration: Current iteration number (for observer metrics tracking)
            **traffic_keys: Traffic identification keys (e.g., pg=3, queue=5)

        Returns:
            Tuple[success, detected]:
                - success: True if verification completed without errors
                - detected: True if Egress Drop was triggered at this value
        """
        assert self.observer is not None, "Observer is required for fine-grained timing"

        try:
            results = []

            for attempt in range(attempts):
                # ===== Step 1: Port preparation (optional) =====
                if drain_buffer:
                    self.ptftest.buffer_ctrl.drain_buffer([dst_port])
                    time.sleep(PORT_TX_CTRL_DELAY)
                    self.ptftest.buffer_ctrl.hold_buffer([dst_port])
                    time.sleep(PORT_TX_CTRL_DELAY)

                # ===== Step 2: Baseline measurement on dst port =====
                dport_cnt_base, _ = _sai_thrift_read_port_counters(
                    self.ptftest.dst_client,
                    self.ptftest.asic_type,
                    port_list["dst"][dst_port]
                )

                if self.verbose and self.observer:
                    self.observer.trace(
                        f"[Egress Drop] Step2-Baseline: "
                        f"EGRESS_DROP={dport_cnt_base[EGRESS_DROP]}, "
                        f"EGRESS_PORT_BUFFER_DROP={dport_cnt_base[EGRESS_PORT_BUFFER_DROP]}"
                    )

                # ===== Step 3: Traffic injection =====
                if value > 0:
                    self.ptftest.buffer_ctrl.send_traffic(src_port, dst_port, value, **traffic_keys)

                # ===== Step 4: Wait for counter refresh =====
                time.sleep(PFC_TRIGGER_DELAY)

                # ===== Step 5: Egress Drop detection on dst port =====
                dport_cnt_curr, _ = _sai_thrift_read_port_counters(
                    self.ptftest.dst_client,
                    self.ptftest.asic_type,
                    port_list["dst"][dst_port]
                )

                egress_drop_triggered = (
                    dport_cnt_curr[EGRESS_DROP] > dport_cnt_base[EGRESS_DROP] or
                    dport_cnt_curr[EGRESS_PORT_BUFFER_DROP] > dport_cnt_base[EGRESS_PORT_BUFFER_DROP]
                )

                if self.verbose and self.observer:
                    egr_drop_diff = dport_cnt_curr[EGRESS_DROP] - dport_cnt_base[EGRESS_DROP]
                    egr_buf_drop_diff = (dport_cnt_curr[EGRESS_PORT_BUFFER_DROP] -
                                         dport_cnt_base[EGRESS_PORT_BUFFER_DROP])
                    self.observer.trace(
                        f"[Egress Drop] Step5-Detection: "
                        f"EGRESS_DROP: base={dport_cnt_base[EGRESS_DROP]}, "
                        f"curr={dport_cnt_curr[EGRESS_DROP]}, diff={egr_drop_diff}, "
                        f"EGRESS_PORT_BUFFER_DROP: base={dport_cnt_base[EGRESS_PORT_BUFFER_DROP]}, "
                        f"curr={dport_cnt_curr[EGRESS_PORT_BUFFER_DROP]}, "
                        f"diff={egr_buf_drop_diff}, triggered={egress_drop_triggered}"
                    )

                results.append(egress_drop_triggered)

                if self.verbose and self.observer:
                    self.observer.trace(
                        f"[Egress Drop] Verification {attempt + 1}/{attempts}: "
                        f"src={src_port}, dst={dst_port}, value={value}, "
                        f"triggered={egress_drop_triggered}"
                    )

            # ===== Result analysis =====
            return_result = (True, results[0])
            if len(results) > 1 and len(set(results)) > 1:
                return_result = (False, False)

            if self.verbose and self.observer:
                self.observer.trace(
                    f"[Egress Drop Executor] Check complete: value={value}, attempts={attempts}, "
                    f"results={results}, final_detected={return_result[1]}, success={return_result[0]}"
                )

            return return_result

        except Exception as e:
            if self.verbose and self.observer:
                self.observer.trace(f"[Egress Drop Executor] Check error: {e}")
            return False, False
