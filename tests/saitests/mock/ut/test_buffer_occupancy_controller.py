#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for BufferOccupancyController class.

Tests cover:
- Initialization
- Buffer hold/drain operations
- Buffer state tracking
- Traffic sending with auto-restore
- Buffer occupancy persistence
- Auto-restoration logic

Coverage target: >90% for buffer_occupancy_controller.py
"""

import pytest
import unittest
from unittest.mock import MagicMock, patch
import sys
import os


# Import the class under test
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../probe"))
from buffer_occupancy_controller import BufferOccupancyController, log_message  # noqa: E402


@pytest.mark.order(5995)
class TestLogMessage(unittest.TestCase):
    """Test log_message utility function."""

    @pytest.mark.order(5995)
    @patch('sys.stderr.write')
    def test_log_message_to_stderr(self, mock_stderr):
        """Test log_message with to_stderr=True."""
        log_message("Test error message", level='error', to_stderr=True)

        # Verify stderr.write was called
        mock_stderr.assert_called_once_with("Test error message\n")


@pytest.mark.order(6000)
class TestBufferOccupancyControllerInitialization(unittest.TestCase):
    """Test BufferOccupancyController initialization."""

    @pytest.mark.order(6000)
    def test_initialization(self):
        """Test controller initializes with all required dependencies."""
        hold_buf_fn = MagicMock()
        drain_buf_fn = MagicMock()
        stream_mgr = MagicMock()
        send_packet_fn = MagicMock()
        ptftest_ref = MagicMock()
        thrift_client = MagicMock()
        asic_type = "broadcom"

        ctrl = BufferOccupancyController(
            hold_buf_fn=hold_buf_fn,
            drain_buf_fn=drain_buf_fn,
            stream_mgr=stream_mgr,
            send_packet_fn=send_packet_fn,
            ptftest_ref=ptftest_ref,
            thrift_client=thrift_client,
            asic_type=asic_type
        )

        # Verify internal state initialization
        assert ctrl._hold_buf_fn == hold_buf_fn
        assert ctrl._drain_buf_fn == drain_buf_fn
        assert ctrl._stream_mgr == stream_mgr
        assert ctrl._send_packet_fn == send_packet_fn
        assert ctrl._ptftest_ref == ptftest_ref
        assert ctrl._thrift_client == thrift_client
        assert ctrl._asic_type == asic_type

        # Verify state tracking initialized as empty
        assert len(ctrl._tx_disabled_ports) == 0
        assert len(ctrl._expected_cached_packets) == 0
        assert len(ctrl._actual_cached_packets) == 0


@pytest.mark.order(6010)
class TestBufferOccupancyControllerHoldBuffer(unittest.TestCase):
    """Test hold_buffer functionality."""

    @pytest.mark.order(6010)
    def test_hold_buffer_single_port(self):
        """Test holding buffer on single port."""
        hold_buf_fn = MagicMock()
        ctrl = BufferOccupancyController(
            hold_buf_fn=hold_buf_fn,
            drain_buf_fn=MagicMock(),
            stream_mgr=MagicMock(),
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        ctrl.hold_buffer([24])

        # Verify hold function called
        hold_buf_fn.assert_called_once()

        # Verify port tracked as disabled
        assert ctrl.is_buffer_held(24)
        assert 24 in ctrl._tx_disabled_ports

    @pytest.mark.order(6020)
    def test_hold_buffer_multiple_ports(self):
        """Test holding buffer on multiple ports."""
        hold_buf_fn = MagicMock()
        ctrl = BufferOccupancyController(
            hold_buf_fn=hold_buf_fn,
            drain_buf_fn=MagicMock(),
            stream_mgr=MagicMock(),
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        ctrl.hold_buffer([24, 28, 32])

        # Verify all ports tracked as disabled
        assert ctrl.is_buffer_held(24)
        assert ctrl.is_buffer_held(28)
        assert ctrl.is_buffer_held(32)
        assert len(ctrl._tx_disabled_ports) == 3


@pytest.mark.order(6030)
class TestBufferOccupancyControllerDrainBuffer(unittest.TestCase):
    """Test drain_buffer functionality."""

    @pytest.mark.order(6030)
    def test_drain_buffer_single_port(self):
        """Test draining buffer on single port."""
        drain_buf_fn = MagicMock()
        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=drain_buf_fn,
            stream_mgr=MagicMock(),
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # First hold then drain
        ctrl.hold_buffer([24])
        assert ctrl.is_buffer_held(24)

        ctrl.drain_buffer([24])

        # Verify drain function called
        drain_buf_fn.assert_called_once()

        # Verify port no longer tracked as disabled
        assert not ctrl.is_buffer_held(24)
        assert 24 not in ctrl._tx_disabled_ports

    @pytest.mark.order(6035)
    def test_drain_buffer_when_no_cached_packets(self):
        """Test drain_buffer handles empty _actual_cached_packets correctly."""
        drain_buf_fn = MagicMock()
        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=drain_buf_fn,
            stream_mgr=MagicMock(),
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Hold buffer but don't send any traffic (so _actual_cached_packets is empty)
        ctrl.hold_buffer([24])

        # Drain should complete without error even when _actual_cached_packets is empty
        ctrl.drain_buffer([24])

        # Verify drain function called
        drain_buf_fn.assert_called_once()
        assert not ctrl.is_buffer_held(24)

    @pytest.mark.order(6040)
    def test_drain_buffer_clears_actual_cached_packets(self):
        """Test drain buffer clears actual cached packet counts."""
        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=MagicMock(),
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Setup: hold buffer and add cached packets
        ctrl.hold_buffer([24])
        key = (11, 24, frozenset([('pg', 3)]))
        ctrl._actual_cached_packets[key] = 100

        # Drain buffer
        ctrl.drain_buffer([24])

        # Verify actual cached count cleared
        assert ctrl._actual_cached_packets.get(key, 0) == 0

    @pytest.mark.order(6041)
    def test_drain_buffer_preserves_other_ports_cached_packets(self):
        """Test drain_buffer only clears cached packets for specified ports, not others."""
        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=MagicMock(),
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Setup: hold buffers on multiple ports and add cached packets
        ctrl.hold_buffer([24, 28])

        # Port 24: PG 3
        key_24_pg3 = (11, 24, frozenset([('pg', 3)]))
        ctrl._actual_cached_packets[key_24_pg3] = 100

        # Port 28: PG 4
        key_28_pg4 = (11, 28, frozenset([('pg', 4)]))
        ctrl._actual_cached_packets[key_28_pg4] = 200

        # Drain only port 24 (NOT port 28)
        ctrl.drain_buffer([24])

        # Verify port 24's cached count is cleared
        assert ctrl._actual_cached_packets.get(key_24_pg3, 0) == 0

        # Verify port 28's cached count is PRESERVED (covers branch 123->122)
        assert ctrl._actual_cached_packets[key_28_pg4] == 200

    @pytest.mark.order(6050)
    def test_drain_buffer_with_last_port_flag(self):
        """Test drain buffer passes last_port flag correctly."""
        drain_buf_fn = MagicMock()
        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=drain_buf_fn,
            stream_mgr=MagicMock(),
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        ctrl.hold_buffer([24])
        ctrl.drain_buffer([24], last_port=True)

        # Verify last_port passed to drain function
        args, kwargs = drain_buf_fn.call_args
        assert 'last_port' in kwargs
        assert kwargs['last_port'] is True


@pytest.mark.order(6060)
class TestBufferOccupancyControllerSendTraffic(unittest.TestCase):
    """Test send_traffic functionality."""

    @pytest.mark.order(6060)
    def test_send_traffic_basic(self):
        """Test basic traffic sending."""
        stream_mgr = MagicMock()
        send_packet_fn = MagicMock()
        ptftest_ref = MagicMock()

        mock_packet = b"test_packet"
        stream_mgr.get_packet.return_value = mock_packet

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=send_packet_fn,
            ptftest_ref=ptftest_ref,
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        ctrl.send_traffic(11, 24, count=10, auto_restore=False, pg=3)

        # Verify packet lookup
        stream_mgr.get_packet.assert_called_once_with(11, 24, pg=3)

        # Verify packet sent
        send_packet_fn.assert_called_once_with(ptftest_ref, 11, mock_packet, 10)

    @pytest.mark.order(6070)
    def test_send_traffic_updates_actual_cached_when_buffer_held(self):
        """Test send_traffic updates actual cached packet count when buffer is held."""
        stream_mgr = MagicMock()
        stream_mgr.get_packet.return_value = b"packet"

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Hold buffer on destination port
        ctrl.hold_buffer([24])

        # Send traffic
        ctrl.send_traffic(11, 24, count=100, auto_restore=False, pg=3)

        # Verify actual cached packets updated
        key = (11, 24, frozenset([('pg', 3)]))
        assert ctrl._actual_cached_packets[key] == 100

    @pytest.mark.order(6080)
    def test_send_traffic_accumulates_actual_cached(self):
        """Test send_traffic accumulates actual cached packets across multiple sends."""
        stream_mgr = MagicMock()
        stream_mgr.get_packet.return_value = b"packet"

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Hold buffer
        ctrl.hold_buffer([24])

        # Send traffic multiple times
        ctrl.send_traffic(11, 24, count=50, auto_restore=False, pg=3)
        ctrl.send_traffic(11, 24, count=30, auto_restore=False, pg=3)

        # Verify accumulated count
        key = (11, 24, frozenset([('pg', 3)]))
        assert ctrl._actual_cached_packets[key] == 80  # 50 + 30

    @pytest.mark.order(6090)
    def test_send_traffic_not_cached_when_buffer_not_held(self):
        """Test send_traffic doesn't update cached count when buffer not held."""
        stream_mgr = MagicMock()
        stream_mgr.get_packet.return_value = b"packet"

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Don't hold buffer
        ctrl.send_traffic(11, 24, count=100, auto_restore=False, pg=3)

        # Verify actual cached packets NOT updated
        key = (11, 24, frozenset([('pg', 3)]))
        assert key not in ctrl._actual_cached_packets

    @pytest.mark.order(6100)
    def test_send_traffic_raises_error_when_packet_not_found(self):
        """Test send_traffic raises error when packet not found."""
        stream_mgr = MagicMock()
        stream_mgr.get_packet.return_value = None  # Packet not found

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Should raise ValueError
        with pytest.raises(ValueError):
            ctrl.send_traffic(11, 24, count=10, auto_restore=False, pg=3)


@pytest.mark.order(6110)
class TestBufferOccupancyControllerPersist(unittest.TestCase):
    """Test persist_buffer_occupancy functionality."""

    @pytest.mark.order(6110)
    def test_persist_sets_expected_count(self):
        """Test persist_buffer_occupancy sets expected cached packet count."""
        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=MagicMock(),
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        ctrl.persist_buffer_occupancy(11, 24, count=500, pg=3)

        # Verify expected count set
        key = (11, 24, frozenset([('pg', 3)]))
        assert ctrl._expected_cached_packets[key] == 500

    @pytest.mark.order(6120)
    def test_persist_does_not_modify_actual_count(self):
        """Test persist_buffer_occupancy does NOT modify actual cached count."""
        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=MagicMock(),
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Set initial actual count
        key = (11, 24, frozenset([('pg', 3)]))
        ctrl._actual_cached_packets[key] = 100

        # Persist with different count
        ctrl.persist_buffer_occupancy(11, 24, count=500, pg=3)

        # Verify actual count unchanged
        assert ctrl._actual_cached_packets[key] == 100

    @pytest.mark.order(6130)
    def test_persist_with_different_traffic_keys(self):
        """Test persist_buffer_occupancy with different traffic keys."""
        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=MagicMock(),
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Persist with pg=3
        ctrl.persist_buffer_occupancy(11, 24, count=300, pg=3)

        # Persist with pg=4
        ctrl.persist_buffer_occupancy(11, 24, count=400, pg=4)

        # Verify both persisted independently
        key1 = (11, 24, frozenset([('pg', 3)]))
        key2 = (11, 24, frozenset([('pg', 4)]))
        assert ctrl._expected_cached_packets[key1] == 300
        assert ctrl._expected_cached_packets[key2] == 400


@pytest.mark.order(6140)
class TestBufferOccupancyControllerAutoRestore(unittest.TestCase):
    """Test auto-restore functionality."""

    @pytest.mark.order(6140)
    def test_auto_restore_when_actual_less_than_expected(self):
        """Test auto-restore sends packets when actual < expected."""
        stream_mgr = MagicMock()
        send_packet_fn = MagicMock()
        ptftest_ref = MagicMock()

        mock_packet = b"restore_packet"
        stream_mgr.get_packet.return_value = mock_packet

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=send_packet_fn,
            ptftest_ref=ptftest_ref,
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Hold buffer
        ctrl.hold_buffer([24])

        # Set expected = 500, actual = 200 (gap of 300)
        key = (11, 24, frozenset([('pg', 3)]))
        ctrl._expected_cached_packets[key] = 500
        ctrl._actual_cached_packets[key] = 200

        # Send traffic with auto_restore=True (default)
        ctrl.send_traffic(11, 24, count=10, pg=3)

        # Verify restoration packets sent (300 packets to restore gap)
        # Should be called twice: once for restore (300), once for new traffic (10)
        assert send_packet_fn.call_count == 2

        # First call should be restoration
        restore_call = send_packet_fn.call_args_list[0]
        assert restore_call[0][3] == 300  # Restore gap (4th arg is count)

        # Second call should be new traffic
        traffic_call = send_packet_fn.call_args_list[1]
        assert traffic_call[0][3] == 10  # 4th arg is count

    @pytest.mark.order(6150)
    def test_auto_restore_skipped_when_auto_restore_false(self):
        """Test auto-restore is skipped when auto_restore=False."""
        stream_mgr = MagicMock()
        send_packet_fn = MagicMock()

        stream_mgr.get_packet.return_value = b"packet"

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=send_packet_fn,
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Setup gap
        key = (11, 24, frozenset([('pg', 3)]))
        ctrl._expected_cached_packets[key] = 500
        ctrl._actual_cached_packets[key] = 200

        # Send with auto_restore=False
        ctrl.send_traffic(11, 24, count=10, auto_restore=False, pg=3)

        # Only new traffic should be sent (no restoration)
        assert send_packet_fn.call_count == 1
        assert send_packet_fn.call_args[0][3] == 10  # 4th arg is count

    @pytest.mark.order(6160)
    def test_auto_restore_updates_actual_to_match_expected(self):
        """Test auto-restore updates actual count to match expected."""
        stream_mgr = MagicMock()
        stream_mgr.get_packet.return_value = b"packet"

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Hold buffer
        ctrl.hold_buffer([24])

        # Set gap
        key = (11, 24, frozenset([('pg', 3)]))
        ctrl._expected_cached_packets[key] = 500
        ctrl._actual_cached_packets[key] = 200

        # Send traffic with auto_restore
        ctrl.send_traffic(11, 24, count=10, pg=3)

        # Actual should now match expected (plus new traffic)
        # After restore: actual = 500, after new traffic: actual = 510
        assert ctrl._actual_cached_packets[key] == 510

    @pytest.mark.order(6170)
    def test_auto_restore_no_action_when_actual_equals_expected(self):
        """Test auto-restore does nothing when actual == expected."""
        stream_mgr = MagicMock()
        send_packet_fn = MagicMock()

        stream_mgr.get_packet.return_value = b"packet"

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=send_packet_fn,
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Set equal counts
        key = (11, 24, frozenset([('pg', 3)]))
        ctrl._expected_cached_packets[key] = 500
        ctrl._actual_cached_packets[key] = 500

        # Send traffic
        ctrl.send_traffic(11, 24, count=10, auto_restore=True, pg=3)

        # Only new traffic sent (no restoration needed)
        assert send_packet_fn.call_count == 1

    @pytest.mark.order(6175)
    def test_auto_restore_handles_missing_packet(self):
        """Test auto-restore handles case when packet cannot be found."""
        stream_mgr = MagicMock()
        send_packet_fn = MagicMock()

        # First call returns None (packet not found), second call returns valid packet
        stream_mgr.get_packet.side_effect = [None, b"new_packet"]

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=send_packet_fn,
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Hold buffer
        ctrl.hold_buffer([24])

        # Set gap (expected > actual)
        key = (11, 24, frozenset([('pg', 3)]))
        ctrl._expected_cached_packets[key] = 500
        ctrl._actual_cached_packets[key] = 200

        # Send traffic with auto_restore - should skip restoration when packet not found
        ctrl.send_traffic(11, 24, count=10, pg=3)

        # Only new traffic should be sent (restoration skipped due to missing packet)
        assert send_packet_fn.call_count == 1
        assert send_packet_fn.call_args[0][3] == 10

    @pytest.mark.order(6176)
    def test_auto_restore_warns_when_buffer_not_held(self):
        """Test auto-restore warns when destination buffer is not held during restoration."""
        stream_mgr = MagicMock()
        send_packet_fn = MagicMock()

        stream_mgr.get_packet.return_value = b"packet"

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=send_packet_fn,
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Set gap but DON'T hold buffer
        key = (11, 24, frozenset([('pg', 3)]))
        ctrl._expected_cached_packets[key] = 500
        ctrl._actual_cached_packets[key] = 200

        # Send traffic with auto_restore when buffer NOT held
        # This should trigger the warning at line 256
        ctrl.send_traffic(11, 24, count=10, auto_restore=True, pg=3)

        # Both restoration and new traffic should be sent
        assert send_packet_fn.call_count == 2

        # But actual should NOT be updated since buffer is not held
        # (the warning case at line 256)
        assert ctrl._actual_cached_packets[key] == 200  # Still original value


@pytest.mark.order(6180)
class TestBufferOccupancyControllerIntegration(unittest.TestCase):
    """Test integration scenarios."""

    @pytest.mark.order(6180)
    def test_multi_pg_workflow(self):
        """Test workflow with multiple PGs."""
        stream_mgr = MagicMock()
        stream_mgr.get_packet.return_value = b"packet"

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=MagicMock(),
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Hold buffer
        ctrl.hold_buffer([24])

        # PG 3: send 1000 packets, persist
        ctrl.send_traffic(11, 24, count=1000, auto_restore=False, pg=3)
        ctrl.persist_buffer_occupancy(11, 24, count=1000, pg=3)

        # PG 4: send 800 packets, persist
        ctrl.send_traffic(11, 24, count=800, auto_restore=False, pg=4)
        ctrl.persist_buffer_occupancy(11, 24, count=800, pg=4)

        # Verify both PGs tracked independently
        key_pg3 = (11, 24, frozenset([('pg', 3)]))
        key_pg4 = (11, 24, frozenset([('pg', 4)]))

        assert ctrl._expected_cached_packets[key_pg3] == 1000
        assert ctrl._expected_cached_packets[key_pg4] == 800
        assert ctrl._actual_cached_packets[key_pg3] == 1000
        assert ctrl._actual_cached_packets[key_pg4] == 800

    @pytest.mark.order(6190)
    def test_drain_and_restore_workflow(self):
        """Test drain followed by restore in next probing phase."""
        stream_mgr = MagicMock()
        send_packet_fn = MagicMock()

        stream_mgr.get_packet.return_value = b"packet"

        ctrl = BufferOccupancyController(
            hold_buf_fn=MagicMock(),
            drain_buf_fn=MagicMock(),
            stream_mgr=stream_mgr,
            send_packet_fn=send_packet_fn,
            ptftest_ref=MagicMock(),
            thrift_client=MagicMock(),
            asic_type="broadcom"
        )

        # Phase 1: establish buffer state
        ctrl.hold_buffer([24])
        ctrl.send_traffic(11, 24, count=500, auto_restore=False, pg=3)
        ctrl.persist_buffer_occupancy(11, 24, count=500, pg=3)

        # Phase 2: drain buffer (clears actual)
        ctrl.drain_buffer([24])

        # Verify actual cleared
        key = (11, 24, frozenset([('pg', 3)]))
        assert ctrl._actual_cached_packets.get(key, 0) == 0

        # Phase 3: re-hold buffer and send new traffic (should auto-restore)
        ctrl.hold_buffer([24])
        send_packet_fn.reset_mock()  # Reset call count

        ctrl.send_traffic(11, 24, count=10, auto_restore=True, pg=3)

        # Should restore 500 packets + send 10 new
        assert send_packet_fn.call_count == 2  # Restore call + traffic call


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
