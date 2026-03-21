"""
BufferOccupancyController - Utility class for managing buffer occupancy state in probing tests

This class extracts common buffer management logic from HeadroomPoolProbe to enable reuse
across different probing scenarios. It provides:
- Port TX control (hold_buffer/drain_buffer) for simulating congestion
- Traffic sending with automatic buffer restoration (send_traffic)
- Persistent buffer state tracking (persist_buffer_occupancy)

Design Philosophy:
- Track disabled state (异常) rather than enabled state (正常) to avoid initialization edge cases
- expected_cached_packets: what buffer state should be maintained (set by persist)
- actual_cached_packets: reflects real send_traffic history (managed by send/release)
- Auto-restore: automatically restore buffer gaps before sending new traffic

Usage:
    # In HdrmPoolProbe.setUp()
    self.buffer_ctrl = BufferOccupancyController(
        hold_buf_fn=self.sai_thrift_port_tx_disable,
        drain_buf_fn=self.sai_thrift_port_tx_enable,
        stream_mgr=self.stream_mgr,
        send_packet_fn=send_packet,
        ptftest_ref=self,
        thrift_client=self.dst_client,
        asic_type=self.asic_type
    )

    # In Executor/Orchestrator
    ptftest.buffer_ctrl.hold_buffer([dst_port])
    ptftest.buffer_ctrl.send_traffic(src_port, dst_port, count, pg=3)
    ptftest.buffer_ctrl.drain_buffer([dst_port])
"""

import logging
import sys
from typing import Set, Dict, Callable, Any, Tuple, FrozenSet


# Local utility for consistent logging (matches sai_qos_tests.py pattern)
def log_message(message: str, level: str = 'info', to_stderr: bool = False) -> None:
    """Log message - import from sai_qos_tests if available, else use print"""
    if to_stderr:
        sys.stderr.write(message + "\n")
    log_funcs = {'debug':    logging.debug,
                 'info':     logging.info,
                 'warning':  logging.info,
                 'error':    logging.error,
                 'critical': logging.error}
    log_fn = log_funcs.get(level.lower(), logging.info)
    log_fn(message)


class BufferOccupancyController:
    """
    Manages buffer occupancy state for probing tests.

    Tracks which ports have TX disabled (buffer held) and maintains
    expected vs actual cached packet counts for automatic restoration.
    """

    def __init__(
        self,
        hold_buf_fn: Callable,
        drain_buf_fn: Callable,
        stream_mgr: Any,
        send_packet_fn: Callable,
        ptftest_ref: Any,
        thrift_client: Any,
        asic_type: str
    ):
        """
        Initialize BufferOccupancyController.

        Args:
            hold_buf_fn: Function to hold buffer (disable port TX)
            drain_buf_fn: Function to drain buffer (enable port TX)
            stream_mgr: StreamManager instance for packet lookup
            send_packet_fn: send_packet function from ptf.testutils
            ptftest_ref: Reference to ptftest instance (for send_packet context)
            thrift_client: Thrift client for DUT (dst_client or src_client)
            asic_type: ASIC type string
        """
        self._hold_buf_fn = hold_buf_fn
        self._drain_buf_fn = drain_buf_fn
        self._stream_mgr = stream_mgr
        self._send_packet_fn = send_packet_fn
        self._ptftest_ref = ptftest_ref
        self._thrift_client = thrift_client
        self._asic_type = asic_type

        # State tracking
        self._tx_disabled_ports: Set[int] = set()  # Ports with TX disabled (buffer held)
        self._expected_cached_packets: Dict[Tuple[int, int, FrozenSet], int] = {}  # Expected
        self._actual_cached_packets: Dict[Tuple[int, int, FrozenSet], int] = {}  # Actual

    # ========== Public API ==========

    def hold_buffer(self, port_ids: list) -> None:
        """
        Hold buffer on ports by disabling TX (simulate congestion).

        Args:
            port_ids: List of port IDs to hold buffer on
        """
        self._hold_buf_fn(self._thrift_client, self._asic_type, port_ids)
        # Track state: add to disabled set
        self._tx_disabled_ports.update(port_ids)

    def drain_buffer(self, port_ids: list, last_port: bool = False) -> None:
        """
        Drain buffer on ports by enabling TX.

        Note: Currently implemented via port TX enable. Future implementations
        may use more granular drain APIs (schedule/pg/queue level).

        Args:
            port_ids: List of port IDs to drain buffer on
            last_port: Whether this is the last port (passed to drain_buf_fn)
        """
        self._drain_buf_fn(self._thrift_client, self._asic_type, port_ids, last_port=last_port)
        # Track state: remove from disabled set
        self._tx_disabled_ports.difference_update(port_ids)
        # Reset actual cached count: when TX enabled, buffer is drained
        for key in list(self._actual_cached_packets.keys()):
            if key[1] in port_ids:  # key[1] is dst_port
                self._actual_cached_packets[key] = 0

    def is_buffer_held(self, port_id: int) -> bool:
        """
        Check if buffer is held on a port (TX disabled).

        Args:
            port_id: Port ID to check

        Returns:
            bool: True if buffer is held (TX disabled), False otherwise
        """
        return port_id in self._tx_disabled_ports

    def send_traffic(
        self,
        src_port_id: int,
        dst_port_id: int,
        count: int = 1,
        auto_restore: bool = True,
        **traffic_keys
    ) -> None:
        """
        Send traffic from src_port to dst_port with automatic buffer restoration.

        Args:
            src_port_id: Source port ID
            dst_port_id: Destination port ID
            count: Number of packets to send
            auto_restore: If True, automatically restore previous buffer states before sending
            **traffic_keys: Traffic identification keys (e.g., pg=3, queue=5)

        Workflow:
            1. Auto-restore: Restore gaps between expected and actual cached packets
            2. Send new traffic
            3. Update actual cached count if dst_port buffer is held
        """
        # Step 1: Auto-restore previous buffer states if enabled
        if auto_restore:
            self._auto_restore_buffers()

        # Step 2: Get packet and send new traffic
        pkt = self._stream_mgr.get_packet(src_port_id, dst_port_id, **traffic_keys)

        if pkt is None:
            log_message(f"ERROR: Cannot find packet for src={src_port_id}, dst={dst_port_id}, keys={traffic_keys}")
            raise ValueError(f"Packet not found for src={src_port_id}, dst={dst_port_id}, keys={traffic_keys}")

        self._send_packet_fn(self._ptftest_ref, src_port_id, pkt, count)

        # Step 3: Update actual cached packets if dst_port buffer is held (packets buffered)
        if self.is_buffer_held(dst_port_id):
            key = (src_port_id, dst_port_id, frozenset(traffic_keys.items()))
            self._actual_cached_packets[key] = self._actual_cached_packets.get(key, 0) + count

    def persist_buffer_occupancy(
        self,
        src_port_id: int,
        dst_port_id: int,
        count: int,
        **traffic_keys
    ) -> None:
        """
        Set expected buffer occupancy for automatic restoration.

        Called by Orchestrator after completing a probing phase to declare desired buffer state.
        Only sets expected - actual reflects real send_traffic history and is managed by
        send_traffic/drain_buffer, not by persist.

        Args:
            src_port_id: Source port ID
            dst_port_id: Destination port ID
            count: Number of packets to maintain in buffer (will be restored by auto_restore)
            **traffic_keys: Traffic identification (e.g., pg=3)

        Design Philosophy (Solution 2):
            - persist sets expected = "what buffer state should be maintained"
            - actual is managed by send_traffic (increments) and drain_buffer (clears)
            - persist does NOT modify actual - that would falsify actual send history
            - Caller must understand: persist after Phase 2 means "maintain this state for next PG"

        Example:
            # After Phase 2 finds ingress_drop_threshold = 20500
            buffer_ctrl.persist_buffer_occupancy(src_port_id=11, dst_port_id=1, count=20500, pg=3)
            # Next PG prepare will drain_buffer (clear actual), then auto_restore will restore 20500
        """
        key = (src_port_id, dst_port_id, frozenset(traffic_keys.items()))
        self._expected_cached_packets[key] = count
        # Do NOT modify actual - it reflects real send_traffic history
        actual = self._actual_cached_packets.get(key, 0)
        log_message(f"Persisted buffer: expected={count}, actual={actual} "
                    f"(port {src_port_id}->{dst_port_id}, keys={traffic_keys})")

    # ========== Internal Methods ==========

    def _auto_restore_buffers(self) -> None:
        """
        Automatically restore buffer gaps between expected and actual cached packets.

        For each flow where actual < expected, send additional packets to restore the gap.
        """
        restoration_needed = []
        for key, expected in self._expected_cached_packets.items():
            actual = self._actual_cached_packets.get(key, 0)
            if actual < expected:
                restoration_needed.append({
                    'key': key,
                    'src_port': key[0],
                    'dst_port': key[1],
                    'traffic_keys': dict(key[2]),
                    'count': expected - actual
                })

        if restoration_needed:
            log_message(f"Auto-restore: {len(restoration_needed)} flows need restoration")
            for item in restoration_needed:
                # Get packet for restoration
                restore_pkt = self._stream_mgr.get_packet(
                    item['src_port'], item['dst_port'], **item['traffic_keys']
                )
                if restore_pkt is None:
                    log_message(f"  WARNING: Cannot find packet for restoration: "
                                f"src={item['src_port']}, dst={item['dst_port']}, keys={item['traffic_keys']}")
                    continue

                self._send_packet_fn(self._ptftest_ref, item['src_port'], restore_pkt, item['count'])

                # Update actual to match expected (only if dst_port buffer is held)
                if self.is_buffer_held(item['dst_port']):
                    self._actual_cached_packets[item['key']] = self._expected_cached_packets[item['key']]
                    log_message(f"  Restored {item['count']} pkts: port {item['src_port']} -> "
                                f"{item['dst_port']} (keys={item['traffic_keys']})")
                else:
                    log_message(f"  WARNING: Skip recording restoration - port {item['dst_port']} "
                                f"TX is enabled (buffer drained)")
