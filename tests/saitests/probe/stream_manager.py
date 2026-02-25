"""
stream_manager.py - Traffic Stream Management for MMU Threshold Probing

This module provides traffic stream management utilities for probing tests:
- PortInfo: Port information container (port_id, mac, ip, vlan)
- FlowConfig: Flow configuration (src/dst ports, packet attributes)
- StreamManager: Flow management and packet generation
- determine_traffic_dmac: Helper for determining destination MAC

These classes were extracted from sai_qos_tests.py to enable reuse
across probing test modules.

Usage:
    from stream_manager import PortInfo, FlowConfig, StreamManager, determine_traffic_dmac

    # Create ports
    src = PortInfo(port_id=11, mac="00:11:22:33:44:55", ip="10.0.0.1")
    dst = PortInfo(port_id=1, mac="00:11:22:33:44:66", ip="10.0.0.2")

    # Create stream manager
    stream_mgr = StreamManager(packet_constructor=my_pkt_fn, rx_port_resolver=my_resolver)

    # Add flows
    stream_mgr.add_flow(FlowConfig(src, dst, dmac=dst.mac, dscp=3))
    stream_mgr.generate_packets()
"""


class PortInfo:
    """Container for port information used in traffic flows.

    Attributes:
        original_port_id: The configured port ID
        actual_port_id: The resolved port ID (for LAG scenarios)
        mac: Port MAC address
        ip: Port IP address
        vlan: Optional VLAN ID
    """
    def __init__(self, port_id, mac, ip, vlan=None):
        self.original_port_id = port_id      # original port id
        self.actual_port_id = None  # actual port id when used as dst port (resolved by get_rx_port)
        self.mac = mac
        self.ip = ip
        self.vlan = vlan

    @property
    def port_id(self):
        """
        Returns the actual port ID if available, otherwise returns the original port ID
        """
        return self.actual_port_id if self.actual_port_id is not None else self.original_port_id


class FlowConfig:
    """Configuration for a single traffic flow.

    Attributes:
        src_port: Source PortInfo
        dst_port: Destination PortInfo
        dmac: Destination MAC address
        dscp: DSCP value (0-63)
        ecn: ECN value (0-3)
        ttl: Time to live
        length: Packet length in bytes
        pkt: Generated packet (set by StreamManager.generate_packets())
    """
    def __init__(self, src_port, dst_port, dmac, dscp=0, ecn=0, ttl=64, length=64):
        self.src_port = src_port
        self.dst_port = dst_port
        self.dmac = dmac
        self.dscp = dscp
        self.ecn = ecn
        self.ttl = ttl
        self.length = length
        self.pkt = None


class StreamManager:
    """Manages traffic flows and packet generation for probing tests.

    Supports both port-based flows (1 src -> N dst) and PG-based flows
    (N src -> 1 dst with different PG/DSCP values).

    Args:
        packet_constructor: Function to construct packets
        rx_port_resolver: Function to resolve actual RX port (for LAG)
    """
    def __init__(self, packet_constructor=None, rx_port_resolver=None):
        # flows: {(src, dst, frozen_keys): FlowConfig}
        # frozen_keys = frozenset(traffic_keys.items()) for hashable dict key
        self.flows = {}
        self.packet_constructor = packet_constructor or self._default_packet_constructor
        self.rx_port_resolver = rx_port_resolver or self._default_rx_port_resolver

    def _default_packet_constructor(self, *args, **kwargs):
        raise NotImplementedError("Packet constructor not provided")

    def _default_rx_port_resolver(self, *args, **kwargs):
        raise NotImplementedError("RX port resolver not provided")

    def add_flow(self, flow_config, **traffic_keys):
        """Add a flow with optional traffic identification keys

        Args:
            flow_config: FlowConfig object with packet attributes
            **traffic_keys: Optional traffic identification (e.g., pg=3, queue=5)
                           Leave empty for port-based flows (backward compatible)

        Example:
            # Port-based flow (old code compatibility)
            stream_mgr.add_flow(FlowConfig(src, dst, ...))

            # PG-based flow (new HeadroomPoolProbing)
            stream_mgr.add_flow(FlowConfig(src, dst, ...), pg=3)
        """
        key = (flow_config.src_port.port_id,
               flow_config.dst_port.port_id,
               frozenset(traffic_keys.items()))
        self.flows[key] = flow_config

    def generate_packets(self):
        """Generate packets for all flows and resolve actual dst ports"""
        for flow_config in self.flows.values():
            spi = flow_config.src_port
            dpi = flow_config.dst_port
            flow_config.pkt = self.packet_constructor(
                flow_config.length, flow_config.dmac, spi.mac,
                spi.ip, dpi.ip, flow_config.dscp, spi.vlan,
                ecn=flow_config.ecn, ttl=flow_config.ttl
            )
            actual_rx_port = self.rx_port_resolver(
                spi.port_id, flow_config.dmac, dpi.ip, spi.ip, dpi.port_id, spi.vlan
            )
            flow_config.dst_port.actual_port_id = actual_rx_port

    def get_port_ids(self, type="all"):
        """Get port IDs from all flows

        Args:
            type: 'src', 'dst', or 'all'

        Returns:
            List of port IDs
        """
        if type not in ["src", "dst", "all"]:
            raise ValueError(f"Invalid type: {type}. Must be 'src', 'dst', or 'all'")

        port_ids = set()

        for flow_config in self.flows.values():
            if type == "src" or type == "all":
                port_ids.add(flow_config.src_port.port_id)
            if type == "dst" or type == "all":
                port_ids.add(flow_config.dst_port.port_id)

        return list(port_ids)

    def get_packet(self, src_port_id, dst_port_id, **traffic_keys):
        """Get packet for a specific flow

        Args:
            src_port_id: Source port ID
            dst_port_id: Destination port ID
            **traffic_keys: Optional traffic identification (e.g., pg=3)
                           Must match the keys used in add_flow()

        Returns:
            Packet object or None if flow not found

        Lookup strategy (strict mode):
            1. Try exact match with provided traffic_keys
            2. If not found, return None (no fallback)

        Example:
            # Port-based lookup (old code)
            pkt = stream_mgr.get_packet(11, 1)

            # PG-based lookup (new code)
            pkt = stream_mgr.get_packet(11, 1, pg=3)
        """
        key = (src_port_id, dst_port_id, frozenset(traffic_keys.items()))
        flow_config = self.flows.get(key)

        if flow_config is not None:
            return flow_config.pkt

        return None


def determine_traffic_dmac(dstport_mac, router_mac, is_dualtor=False, def_vlan_mac=None):
    """Determine the appropriate destination MAC address based on configuration.

    Args:
        dstport_mac: Destination port MAC address
        router_mac: Router MAC address
        is_dualtor: Whether this is a dual-ToR configuration
        def_vlan_mac: Default VLAN MAC (used in dual-ToR)

    Returns:
        The appropriate destination MAC address
    """
    if is_dualtor and def_vlan_mac is not None:
        return def_vlan_mac
    return router_mac if router_mac != "" else dstport_mac
