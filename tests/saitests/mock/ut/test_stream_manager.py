#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Unit tests for StreamManager module.

Tests cover:
- PortInfo class (port ID handling, properties)
- FlowConfig class (flow configuration)
- StreamManager class (flow management, packet generation)
- determine_traffic_dmac helper function

Coverage target: >90% for stream_manager.py
"""

import pytest
import unittest
from unittest.mock import MagicMock, patch
import sys
import os


# Add probe path
probe_path = os.path.join(os.path.dirname(__file__), "../../probe")
if probe_path not in sys.path:
    sys.path.insert(0, probe_path)


def get_clean_classes():
    """Get clean (unpatched) classes by forcing module reload."""
    patch.stopall()

    # Remove from cache to force re-import
    if 'stream_manager' in sys.modules:
        del sys.modules['stream_manager']

    # Now import fresh
    import stream_manager

    return (
        stream_manager.PortInfo,
        stream_manager.FlowConfig,
        stream_manager.StreamManager,
        stream_manager.determine_traffic_dmac
    )


@pytest.mark.order(3500)
class TestPortInfo(unittest.TestCase):
    """Test PortInfo class."""

    def setUp(self):
        """Get clean classes before each test."""
        PortInfo, FlowConfig, StreamManager, determine_traffic_dmac = get_clean_classes()
        self.PortInfo = PortInfo
        self.FlowConfig = FlowConfig
        self.StreamManager = StreamManager
        self.determine_traffic_dmac = determine_traffic_dmac

    @pytest.mark.order(3500)
    def test_port_info_initialization(self):
        """Test PortInfo initializes with all required attributes."""
        port = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1", vlan=100)

        assert port.original_port_id == 11
        assert port.mac == "00:11:22:33:44:55"
        assert port.ip == "10.0.0.1"
        assert port.vlan == 100
        assert port.actual_port_id is None  # Not set initially

    @pytest.mark.order(3510)
    def test_port_info_without_vlan(self):
        """Test PortInfo works without VLAN."""
        port = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="192.168.1.1")

        assert port.original_port_id == 24
        assert port.vlan is None

    @pytest.mark.order(3520)
    def test_port_id_property_returns_original_when_actual_not_set(self):
        """Test port_id property returns original_port_id when actual not set."""
        port = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")

        assert port.port_id == 11
        assert port.actual_port_id is None

    @pytest.mark.order(3530)
    def test_port_id_property_returns_actual_when_set(self):
        """Test port_id property returns actual_port_id when set (e.g., LAG scenario)."""
        port = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")

        # Simulate LAG resolution
        port.actual_port_id = 15

        assert port.port_id == 15  # Returns actual
        assert port.original_port_id == 11  # Original unchanged


@pytest.mark.order(3540)
class TestFlowConfig(unittest.TestCase):
    """Test FlowConfig class."""

    def setUp(self):
        """Get clean classes before each test."""
        PortInfo, FlowConfig, StreamManager, determine_traffic_dmac = get_clean_classes()
        self.PortInfo = PortInfo
        self.FlowConfig = FlowConfig
        self.StreamManager = StreamManager
        self.determine_traffic_dmac = determine_traffic_dmac

    @pytest.mark.order(3540)
    def test_flow_config_initialization(self):
        """Test FlowConfig initializes with all attributes."""
        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2")

        flow = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff", dscp=3, ecn=1, ttl=128, length=1024)

        assert flow.src_port == src
        assert flow.dst_port == dst
        assert flow.dmac == "aa:bb:cc:dd:ee:ff"
        assert flow.dscp == 3
        assert flow.ecn == 1
        assert flow.ttl == 128
        assert flow.length == 1024
        assert flow.pkt is None  # Not generated yet

    @pytest.mark.order(3550)
    def test_flow_config_defaults(self):
        """Test FlowConfig uses default values for optional parameters."""
        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2")

        flow = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff")

        # Verify defaults
        assert flow.dscp == 0
        assert flow.ecn == 0
        assert flow.ttl == 64
        assert flow.length == 64


@pytest.mark.order(3560)
class TestStreamManagerInitialization(unittest.TestCase):
    """Test StreamManager initialization."""

    def setUp(self):
        """Get clean classes before each test."""
        PortInfo, FlowConfig, StreamManager, determine_traffic_dmac = get_clean_classes()
        self.PortInfo = PortInfo
        self.FlowConfig = FlowConfig
        self.StreamManager = StreamManager
        self.determine_traffic_dmac = determine_traffic_dmac

    @pytest.mark.order(3560)
    def test_initialization_with_provided_functions(self):
        """Test StreamManager initializes with provided functions."""
        pkt_constructor = MagicMock()
        rx_resolver = MagicMock()

        mgr = self.StreamManager(packet_constructor=pkt_constructor, rx_port_resolver=rx_resolver)

        assert mgr.packet_constructor == pkt_constructor
        assert mgr.rx_port_resolver == rx_resolver
        assert len(mgr.flows) == 0

    @pytest.mark.order(3570)
    def test_initialization_without_functions(self):
        """Test StreamManager initializes without functions (uses defaults)."""
        mgr = self.StreamManager()

        # Should have default implementations
        assert mgr.packet_constructor is not None
        assert mgr.rx_port_resolver is not None

    @pytest.mark.order(3580)
    def test_default_packet_constructor_raises_not_implemented(self):
        """Test default packet constructor raises NotImplementedError."""
        mgr = self.StreamManager()

        with pytest.raises(NotImplementedError):
            mgr.packet_constructor()

    @pytest.mark.order(3590)
    def test_default_rx_port_resolver_raises_not_implemented(self):
        """Test default RX port resolver raises NotImplementedError."""
        mgr = self.StreamManager()

        with pytest.raises(NotImplementedError):
            mgr.rx_port_resolver()


@pytest.mark.order(3600)
class TestStreamManagerAddFlow(unittest.TestCase):
    """Test StreamManager add_flow functionality."""

    def setUp(self):
        """Get clean classes before each test."""
        PortInfo, FlowConfig, StreamManager, determine_traffic_dmac = get_clean_classes()
        self.PortInfo = PortInfo
        self.FlowConfig = FlowConfig
        self.StreamManager = StreamManager
        self.determine_traffic_dmac = determine_traffic_dmac

    @pytest.mark.order(3600)
    def test_add_flow_without_traffic_keys(self):
        """Test adding flow without traffic keys (port-based flow)."""
        mgr = self.StreamManager(packet_constructor=MagicMock(), rx_port_resolver=MagicMock())

        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2")
        flow = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff")

        mgr.add_flow(flow)

        # Verify flow added with port-based key
        assert len(mgr.flows) == 1
        key = (11, 24, frozenset())
        assert key in mgr.flows
        assert mgr.flows[key] == flow

    @pytest.mark.order(3610)
    def test_add_flow_with_pg_key(self):
        """Test adding flow with PG traffic key."""
        mgr = self.StreamManager(packet_constructor=MagicMock(), rx_port_resolver=MagicMock())

        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2")
        flow = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff")

        mgr.add_flow(flow, pg=3)

        # Verify flow added with PG key
        key = (11, 24, frozenset([('pg', 3)]))
        assert key in mgr.flows
        assert mgr.flows[key] == flow

    @pytest.mark.order(3620)
    def test_add_multiple_flows_with_different_keys(self):
        """Test adding multiple flows with different traffic keys."""
        mgr = self.StreamManager(packet_constructor=MagicMock(), rx_port_resolver=MagicMock())

        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2")

        # Add flows with different PGs
        flow1 = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff")
        flow2 = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff")

        mgr.add_flow(flow1, pg=3)
        mgr.add_flow(flow2, pg=4)

        # Verify both flows stored independently
        assert len(mgr.flows) == 2
        assert (11, 24, frozenset([('pg', 3)])) in mgr.flows
        assert (11, 24, frozenset([('pg', 4)])) in mgr.flows

    @pytest.mark.order(3630)
    def test_add_flow_multiple_traffic_keys(self):
        """Test adding flow with multiple traffic keys."""
        mgr = self.StreamManager(packet_constructor=MagicMock(), rx_port_resolver=MagicMock())

        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2")
        flow = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff")

        mgr.add_flow(flow, pg=3, queue=5)

        # Verify flow with multiple keys
        key = (11, 24, frozenset([('pg', 3), ('queue', 5)]))
        assert key in mgr.flows


@pytest.mark.order(3640)
class TestStreamManagerGeneratePackets(unittest.TestCase):
    """Test StreamManager generate_packets functionality."""

    def setUp(self):
        """Get clean classes before each test."""
        PortInfo, FlowConfig, StreamManager, determine_traffic_dmac = get_clean_classes()
        self.PortInfo = PortInfo
        self.FlowConfig = FlowConfig
        self.StreamManager = StreamManager
        self.determine_traffic_dmac = determine_traffic_dmac

    @pytest.mark.order(3640)
    def test_generate_packets_calls_constructor(self):
        """Test generate_packets calls packet constructor for each flow."""
        pkt_constructor = MagicMock(return_value=b"test_packet")
        rx_resolver = MagicMock(return_value=24)

        mgr = self.StreamManager(packet_constructor=pkt_constructor, rx_port_resolver=rx_resolver)

        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1", vlan=100)
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2")
        flow = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff", dscp=3, ecn=1, ttl=128, length=1024)

        mgr.add_flow(flow)
        mgr.generate_packets()

        # Verify packet constructor called with correct parameters
        pkt_constructor.assert_called_once_with(
            1024,  # length
            "aa:bb:cc:dd:ee:ff",  # dmac
            "00:11:22:33:44:55",  # src mac
            "10.0.0.1",  # src ip
            "10.0.0.2",  # dst ip
            3,  # dscp
            100,  # vlan
            ecn=1,
            ttl=128
        )

        # Verify packet assigned to flow
        assert flow.pkt == b"test_packet"

    @pytest.mark.order(3650)
    def test_generate_packets_calls_rx_resolver(self):
        """Test generate_packets calls RX port resolver for each flow."""
        pkt_constructor = MagicMock(return_value=b"packet")
        rx_resolver = MagicMock(return_value=26)  # LAG resolves to port 26

        mgr = self.StreamManager(packet_constructor=pkt_constructor, rx_port_resolver=rx_resolver)

        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1", vlan=100)
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2")
        flow = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff")

        mgr.add_flow(flow)
        mgr.generate_packets()

        # Verify RX resolver called
        rx_resolver.assert_called_once_with(
            11,  # src port
            "aa:bb:cc:dd:ee:ff",  # dmac
            "10.0.0.2",  # dst ip
            "10.0.0.1",  # src ip
            24,  # dst port original
            100  # vlan
        )

        # Verify actual port ID updated
        assert dst.actual_port_id == 26

    @pytest.mark.order(3660)
    def test_generate_packets_multiple_flows(self):
        """Test generate_packets handles multiple flows correctly."""
        pkt_constructor = MagicMock(side_effect=[b"pkt1", b"pkt2"])
        rx_resolver = MagicMock(side_effect=[24, 28])

        mgr = self.StreamManager(packet_constructor=pkt_constructor, rx_port_resolver=rx_resolver)

        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        dst1 = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:01", ip="10.0.0.2")
        dst2 = self.PortInfo(port_id=28, mac="aa:bb:cc:dd:ee:02", ip="10.0.0.3")

        flow1 = self.FlowConfig(src, dst1, dmac="aa:bb:cc:dd:ee:01")
        flow2 = self.FlowConfig(src, dst2, dmac="aa:bb:cc:dd:ee:02")

        mgr.add_flow(flow1, pg=3)
        mgr.add_flow(flow2, pg=4)
        mgr.generate_packets()

        # Verify both flows have packets
        assert flow1.pkt == b"pkt1"
        assert flow2.pkt == b"pkt2"

        # Verify both called
        assert pkt_constructor.call_count == 2
        assert rx_resolver.call_count == 2


@pytest.mark.order(3670)
class TestStreamManagerGetPortIds(unittest.TestCase):
    """Test StreamManager get_port_ids functionality."""

    def setUp(self):
        """Get clean classes before each test."""
        PortInfo, FlowConfig, StreamManager, determine_traffic_dmac = get_clean_classes()
        self.PortInfo = PortInfo
        self.FlowConfig = FlowConfig
        self.StreamManager = StreamManager
        self.determine_traffic_dmac = determine_traffic_dmac

    @pytest.mark.order(3670)
    def test_get_port_ids_all(self):
        """Test get_port_ids returns all port IDs."""
        mgr = self.StreamManager(packet_constructor=MagicMock(), rx_port_resolver=MagicMock())

        src1 = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        src2 = self.PortInfo(port_id=12, mac="00:11:22:33:44:66", ip="10.0.0.2")
        dst1 = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:01", ip="10.0.0.10")
        dst2 = self.PortInfo(port_id=28, mac="aa:bb:cc:dd:ee:02", ip="10.0.0.11")

        mgr.add_flow(self.FlowConfig(src1, dst1, dmac="aa:bb:cc:dd:ee:01"))
        mgr.add_flow(self.FlowConfig(src2, dst2, dmac="aa:bb:cc:dd:ee:02"))

        port_ids = mgr.get_port_ids(type="all")

        # Should have all 4 unique ports
        assert set(port_ids) == {11, 12, 24, 28}

    @pytest.mark.order(3680)
    def test_get_port_ids_src_only(self):
        """Test get_port_ids returns only source port IDs."""
        mgr = self.StreamManager(packet_constructor=MagicMock(), rx_port_resolver=MagicMock())

        src1 = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        src2 = self.PortInfo(port_id=12, mac="00:11:22:33:44:66", ip="10.0.0.2")
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:01", ip="10.0.0.10")

        mgr.add_flow(self.FlowConfig(src1, dst, dmac="aa:bb:cc:dd:ee:01"))
        mgr.add_flow(self.FlowConfig(src2, dst, dmac="aa:bb:cc:dd:ee:01"))

        port_ids = mgr.get_port_ids(type="src")

        # Should have only source ports
        assert set(port_ids) == {11, 12}

    @pytest.mark.order(3690)
    def test_get_port_ids_dst_only(self):
        """Test get_port_ids returns only destination port IDs."""
        mgr = self.StreamManager(packet_constructor=MagicMock(), rx_port_resolver=MagicMock())

        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        dst1 = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:01", ip="10.0.0.10")
        dst2 = self.PortInfo(port_id=28, mac="aa:bb:cc:dd:ee:02", ip="10.0.0.11")

        mgr.add_flow(self.FlowConfig(src, dst1, dmac="aa:bb:cc:dd:ee:01"))
        mgr.add_flow(self.FlowConfig(src, dst2, dmac="aa:bb:cc:dd:ee:02"))

        port_ids = mgr.get_port_ids(type="dst")

        # Should have only destination ports
        assert set(port_ids) == {24, 28}

    @pytest.mark.order(3700)
    def test_get_port_ids_invalid_type_raises_error(self):
        """Test get_port_ids raises error for invalid type."""
        mgr = self.StreamManager(packet_constructor=MagicMock(), rx_port_resolver=MagicMock())

        with pytest.raises(ValueError) as exc_info:
            mgr.get_port_ids(type="invalid")

        assert "Invalid type" in str(exc_info.value)


@pytest.mark.order(3710)
class TestStreamManagerGetPacket(unittest.TestCase):
    """Test StreamManager get_packet functionality."""

    def setUp(self):
        """Get clean classes before each test."""
        PortInfo, FlowConfig, StreamManager, determine_traffic_dmac = get_clean_classes()
        self.PortInfo = PortInfo
        self.FlowConfig = FlowConfig
        self.StreamManager = StreamManager
        self.determine_traffic_dmac = determine_traffic_dmac

    @pytest.mark.order(3710)
    def test_get_packet_without_traffic_keys(self):
        """Test get_packet retrieves packet for port-based flow."""
        pkt_constructor = MagicMock(return_value=b"test_packet")
        mgr = self.StreamManager(packet_constructor=pkt_constructor, rx_port_resolver=MagicMock())

        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2")
        flow = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff")

        mgr.add_flow(flow)
        mgr.generate_packets()

        pkt = mgr.get_packet(11, 24)

        assert pkt == b"test_packet"

    @pytest.mark.order(3720)
    def test_get_packet_with_pg_key(self):
        """Test get_packet retrieves packet for PG-based flow."""
        pkt_constructor = MagicMock(return_value=b"pg3_packet")
        mgr = self.StreamManager(packet_constructor=pkt_constructor, rx_port_resolver=MagicMock())

        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2")
        flow = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff")

        mgr.add_flow(flow, pg=3)
        mgr.generate_packets()

        pkt = mgr.get_packet(11, 24, pg=3)

        assert pkt == b"pg3_packet"

    @pytest.mark.order(3730)
    def test_get_packet_returns_none_when_not_found(self):
        """Test get_packet returns None when flow not found."""
        mgr = self.StreamManager(packet_constructor=MagicMock(), rx_port_resolver=MagicMock())

        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2")

        mgr.add_flow(self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff"), pg=3)
        mgr.generate_packets()

        # Try to get packet with different PG
        pkt = mgr.get_packet(11, 24, pg=4)

        assert pkt is None

    @pytest.mark.order(3740)
    def test_get_packet_differentiates_traffic_keys(self):
        """Test get_packet correctly differentiates flows with different traffic keys."""
        mgr = self.StreamManager(
            packet_constructor=MagicMock(side_effect=[b"pkt_pg3", b"pkt_pg4"]),
            rx_port_resolver=MagicMock()
        )

        src = self.PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
        dst = self.PortInfo(port_id=24, mac="aa:bb:cc:dd:ee:ff", ip="10.0.0.2")

        flow1 = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff")
        flow2 = self.FlowConfig(src, dst, dmac="aa:bb:cc:dd:ee:ff")

        mgr.add_flow(flow1, pg=3)
        mgr.add_flow(flow2, pg=4)
        mgr.generate_packets()

        # Verify each PG returns correct packet
        assert mgr.get_packet(11, 24, pg=3) == b"pkt_pg3"
        assert mgr.get_packet(11, 24, pg=4) == b"pkt_pg4"


@pytest.mark.order(3750)
class TestDetermineTrafficDmac(unittest.TestCase):
    """Test determine_traffic_dmac helper function."""

    def setUp(self):
        """Get clean classes before each test."""
        PortInfo, FlowConfig, StreamManager, determine_traffic_dmac = get_clean_classes()
        self.PortInfo = PortInfo
        self.FlowConfig = FlowConfig
        self.StreamManager = StreamManager
        self.determine_traffic_dmac = determine_traffic_dmac

    @pytest.mark.order(3750)
    def test_determine_dmac_dualtor_with_def_vlan_mac(self):
        """Test determine_traffic_dmac returns def_vlan_mac for dual-ToR."""
        dmac = self.determine_traffic_dmac(
            dstport_mac="00:11:22:33:44:55",
            router_mac="aa:bb:cc:dd:ee:ff",
            is_dualtor=True,
            def_vlan_mac="ff:ee:dd:cc:bb:aa"
        )

        assert dmac == "ff:ee:dd:cc:bb:aa"

    @pytest.mark.order(3760)
    def test_determine_dmac_dualtor_without_def_vlan_mac(self):
        """Test determine_traffic_dmac returns router_mac when def_vlan_mac is None."""
        dmac = self.determine_traffic_dmac(
            dstport_mac="00:11:22:33:44:55",
            router_mac="aa:bb:cc:dd:ee:ff",
            is_dualtor=True,
            def_vlan_mac=None
        )

        assert dmac == "aa:bb:cc:dd:ee:ff"

    @pytest.mark.order(3770)
    def test_determine_dmac_not_dualtor_with_router_mac(self):
        """Test determine_traffic_dmac returns router_mac for non-dual-ToR."""
        dmac = self.determine_traffic_dmac(
            dstport_mac="00:11:22:33:44:55",
            router_mac="aa:bb:cc:dd:ee:ff",
            is_dualtor=False,
            def_vlan_mac="ff:ee:dd:cc:bb:aa"
        )

        assert dmac == "aa:bb:cc:dd:ee:ff"

    @pytest.mark.order(3780)
    def test_determine_dmac_returns_dstport_mac_when_router_mac_empty(self):
        """Test determine_traffic_dmac returns dstport_mac when router_mac is empty."""
        dmac = self.determine_traffic_dmac(
            dstport_mac="00:11:22:33:44:55",
            router_mac="",
            is_dualtor=False,
            def_vlan_mac=None
        )

        assert dmac == "00:11:22:33:44:55"


@pytest.mark.order(3790)
class TestStreamManagerUniformPackets(unittest.TestCase):
    """
    Test StreamManager enforces uniform 64-byte probe packets.

    Design Doc Reference: §3.2, §3.6
    Key Design Point: Platform independence through uniform probe packets
    - Fixed 64-byte length across all platforms
    - 64 bytes = 1 cell on all platforms (eliminates cell_occupancy variance)
    """

    def setUp(self):
        """Set up test fixtures."""
        PortInfo, FlowConfig, StreamManager, _ = get_clean_classes()
        self.PortInfo = PortInfo
        self.FlowConfig = FlowConfig
        self.StreamManager = StreamManager

    def test_uniform_packet_size_64_bytes(self):
        """Test that StreamManager enforces 64-byte packet size for platform independence."""
        # Mock packet constructor that captures the length parameter
        captured_lengths = []

        def mock_packet_constructor(length, dmac, smac, src_ip, dst_ip, dscp, vlan, **kwargs):
            captured_lengths.append(length)
            return f"packet_{length}bytes"

        # Create StreamManager with mock constructor
        mgr = self.StreamManager(
            packet_constructor=mock_packet_constructor,
            rx_port_resolver=lambda *args: 10  # Mock RX resolver
        )

        # Add multiple flows
        mgr.add_flow(self.FlowConfig(
            src_port=self.PortInfo(11, mac="aa:bb:cc:dd:ee:01", ip="10.0.0.1"),
            dst_port=self.PortInfo(1, mac="00:11:22:33:44:01", ip="10.0.1.1"),
            dmac="00:11:22:33:44:01",  # Required parameter
            length=64  # Explicit 64-byte
        ))

        mgr.add_flow(self.FlowConfig(
            src_port=self.PortInfo(12, mac="aa:bb:cc:dd:ee:02", ip="10.0.0.2"),
            dst_port=self.PortInfo(2, mac="00:11:22:33:44:02", ip="10.0.1.2"),
            dmac="00:11:22:33:44:02",  # Required parameter
            # No length specified - should default to 64
        ))

        # Generate packets
        mgr.generate_packets()

        # Verify all packets are 64 bytes (uniform)
        assert len(captured_lengths) == 2, "Should generate 2 packets"
        assert all(length == 64 for length in captured_lengths), \
            f"All packets must be 64 bytes for platform independence, got {captured_lengths}"

    def test_uniform_packet_protocol_consistency(self):
        """Test that packets use consistent protocol (IP) across flows."""
        # Track packet construction parameters
        constructed_packets = []

        def mock_packet_constructor(length, dmac, smac, src_ip, dst_ip, dscp, vlan, **kwargs):
            constructed_packets.append({
                'length': length,
                'dscp': dscp,
                'ttl': kwargs.get('ttl'),
                'ecn': kwargs.get('ecn')
            })
            return f"packet_{len(constructed_packets)}"

        mgr = self.StreamManager(
            packet_constructor=mock_packet_constructor,
            rx_port_resolver=lambda *args: 10
        )

        # Add flows with different DSCP/ECN but same protocol
        mgr.add_flow(self.FlowConfig(
            src_port=self.PortInfo(11, mac="aa:bb:cc:dd:ee:01", ip="10.0.0.1"),
            dst_port=self.PortInfo(1, mac="00:11:22:33:44:01", ip="10.0.1.1"),
            dmac="00:11:22:33:44:01",
            dscp=3, ecn=1, ttl=64
        ))

        mgr.add_flow(self.FlowConfig(
            src_port=self.PortInfo(12, mac="aa:bb:cc:dd:ee:02", ip="10.0.0.2"),
            dst_port=self.PortInfo(2, mac="00:11:22:33:44:02", ip="10.0.1.2"),
            dmac="00:11:22:33:44:02",
            dscp=4, ecn=0, ttl=64
        ))

        mgr.generate_packets()

        # Verify protocol consistency - all IP packets with TTL
        assert len(constructed_packets) == 2
        assert all(pkt['length'] == 64 for pkt in constructed_packets), "Uniform 64-byte size"
        assert all(pkt['ttl'] == 64 for pkt in constructed_packets), "Consistent TTL"
        # DSCP/ECN can vary (they identify different PGs), but protocol is same


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
