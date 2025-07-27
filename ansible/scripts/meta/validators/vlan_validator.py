"""
VlanValidator - Validates VLAN configuration validity and ranges using BFS traversal design
"""

import re
from collections import deque
from .base_validator import GroupValidator, ValidatorContext
from .validator_factory import register_validator


@register_validator("vlan")
class VlanValidator(GroupValidator):
    """Validates VLAN configurations using BFS traversal from DUTs through connected devices"""

    def __init__(self, config=None):
        super().__init__(
            name="vlan",
            description="Validates VLAN configurations using BFS traversal from DUTs through connected devices",
            category="networking"
        )
        self.config = config or {}
        self.min_vlan_id = self.config.get('min_vlan_id', 1)
        self.max_vlan_id = self.config.get('max_vlan_id', 4096)

    def _validate(self, context: ValidatorContext) -> None:
        """
        Validate VLAN configurations using BFS traversal from DUTs

        Args:
            context: ValidatorContext containing testbed and connection graph data
        """
        conn_graph = context.get_connection_graph()

        # Collect topology data needed for BFS traversal
        topology_data = self._collect_topology_data(conn_graph)
        if not topology_data:
            self.logger.info("VLAN validation summary: No topology data found for VLAN validation")
            return

        # Validate VLANs using BFS traversal
        validation_stats = self._validate_vlans_with_bfs(topology_data)

        # Add metadata
        self.result.metadata.update({
            "devices_visited": validation_stats["devices_visited"],
            "links_processed": validation_stats["links_processed"],
            "unique_vlans": validation_stats["unique_vlans"],
            "vlan_range": validation_stats["vlan_range"],
            "min_vlan_id": self.min_vlan_id,
            "max_vlan_id": self.max_vlan_id
        })

        if self.result.success:
            self.result.add_issue(
                'I7000',
                {
                    "devices_visited": validation_stats['devices_visited'],
                    "links_processed": validation_stats['links_processed'],
                    "unique_vlans": validation_stats['unique_vlans']
                }
            )

    def _collect_topology_data(self, conn_graph):
        """
        Collect topology data needed for BFS traversal

        Args:
            conn_graph: Connection graph data

        Returns:
            dict: Topology data with devices, connections, and VLAN configurations
        """
        devices = conn_graph.get('devices', {})
        device_conn = conn_graph.get('links', {})
        port_vlans = conn_graph.get('port_vlans', {})

        # Find DUT devices (DevSonic type)
        dut_devices = []
        for device_name, device_info in devices.items():
            if isinstance(device_info, dict) and device_info.get('Type') == 'DevSonic':
                dut_devices.append(device_name)

        if not dut_devices:
            self.result.add_issue('E7001', {"devices_checked": "all"})
            return None

        return {
            'devices': devices,
            'links': device_conn,
            'port_vlans': port_vlans,
            'dut_devices': dut_devices
        }

    def _validate_vlans_with_bfs(self, topology_data):
        """
        Validate VLANs using BFS traversal from DUT devices with new algorithm

        Args:
            topology_data: Topology data containing devices and connections

        Returns:
            dict: Validation statistics
        """
        visited_devices = set()
        visited_links = set()
        all_vlans = set()
        devices_visited = 0
        links_processed = 0

        # Hash table to store VLAN IDs per device
        device_vlans_table = {}
        # Hash table to store tracked ports per device (ports visited during BFS)
        device_tracked_ports = {}

        # Start unified BFS from all DUT devices
        queue = deque()

        # Add all DUT devices to the initial queue
        for dut_device in topology_data['dut_devices']:
            if dut_device not in visited_devices:
                queue.append(dut_device)
                visited_devices.add(dut_device)
                self.logger.debug(f"Added DUT to initial queue: {dut_device}")

        # Single BFS traversal through the entire topology
        while queue:
            current_device = queue.popleft()
            devices_visited += 1
            self.logger.debug(f"Visiting device: {current_device}")

            # Step 1: Enumerate all non-visited links and store VLAN IDs for peer devices
            peer_vlans = self._process_peer_links(
                current_device, topology_data, visited_links, device_vlans_table, device_tracked_ports
            )
            links_processed += peer_vlans['links_processed']

            # Step 2: Load and validate VLAN IDs for current device
            current_device_vlans = self._validate_current_device_vlans(
                current_device, topology_data, device_vlans_table, device_tracked_ports,
                peer_vlans['peer_devices']
            )
            all_vlans.update(current_device_vlans)

            # Add peer devices to queue for BFS traversal
            for peer_device in peer_vlans['peer_devices']:
                if peer_device not in visited_devices:
                    visited_devices.add(peer_device)
                    queue.append(peer_device)
                    self.logger.debug(f"Added peer device to queue: {peer_device}")

        return {
            "devices_visited": devices_visited,
            "links_processed": links_processed,
            "unique_vlans": len(all_vlans),
            "vlan_range": f"{min(all_vlans) if all_vlans else 0}-{max(all_vlans) if all_vlans else 0}"
        }

    def _process_peer_links(self, current_device, topology_data, visited_links, device_vlans_table,
                            device_tracked_ports):
        """
        Process all non-visited links for current device and store VLAN IDs for peer devices

        Args:
            current_device: Current device being processed
            topology_data: Topology data
            visited_links: Set of already visited links
            device_vlans_table: Hash table to store VLAN IDs per device
            device_tracked_ports: Hash table to store tracked ports per device

        Returns:
            dict: Contains peer_devices list and links_processed count
        """
        peer_devices = set()
        links_processed = 0

        # Get device connections
        device_connections = topology_data.get('links', {}).get(current_device, {})

        for port_name, connection_info in device_connections.items():
            if not isinstance(connection_info, dict):
                continue

            peer_device = connection_info.get('peerdevice')
            peer_port = connection_info.get('peerport')

            if not peer_device or not peer_port:
                continue

            # Create unique link identifier
            link_id = tuple(sorted([
                (current_device, port_name),
                (peer_device, peer_port)
            ]))

            if link_id not in visited_links:
                visited_links.add(link_id)
                links_processed += 1
                peer_devices.add(peer_device)

                # Get VLAN IDs from CURRENT device port (not peer port)
                current_port_vlans = self._get_port_vlans(current_device, port_name, topology_data)

                # Store VLAN IDs from current device port for the peer device
                # This means: "peer device should expect to see these VLANs from this link"
                if peer_device not in device_vlans_table:
                    device_vlans_table[peer_device] = set()
                device_vlans_table[peer_device].update(current_port_vlans)

                # Track which peer port was visited (the port that should be validated)
                if peer_device not in device_tracked_ports:
                    device_tracked_ports[peer_device] = set()
                device_tracked_ports[peer_device].add(peer_port)

        return {
            'peer_devices': peer_devices,
            'links_processed': links_processed
        }

    def _validate_current_device_vlans(self, current_device, topology_data, device_vlans_table,
                                       device_tracked_ports, peer_devices):
        """
        Load and validate VLAN IDs for current device

        Args:
            current_device: Current device being processed
            topology_data: Topology data
            device_vlans_table: Hash table with VLAN IDs per device
            device_tracked_ports: Hash table with tracked ports per device
            peer_devices: Set of peer devices for this device

        Returns:
            set: All VLAN IDs found on current device
        """
        all_device_vlans = set()

        # Collect all VLAN IDs from all ports on current device
        port_vlans_config = topology_data.get('port_vlans', {}).get(current_device, {})

        for port_name, vlan_config in port_vlans_config.items():
            if not isinstance(vlan_config, dict):
                self.result.add_issue(
                    'E7002',
                    {"device": current_device, "port": port_name, "actual_type": type(vlan_config).__name__}
                )
                continue

            port_vlans = self._get_port_vlans(current_device, port_name, topology_data)
            all_device_vlans.update(port_vlans)

        # Only validate VLANs that were stored/tracked from peer devices in BFS traversal
        stored_vlans = device_vlans_table.get(current_device, set())
        tracked_ports = device_tracked_ports.get(current_device, set())
        if stored_vlans and tracked_ports:
            # Simple rule: Check for duplicates only among tracked ports
            self._validate_simple_vlan_uniqueness(current_device, stored_vlans, tracked_ports, topology_data)

        return all_device_vlans

    def _validate_simple_vlan_uniqueness(self, device_name, tracked_vlans, tracked_ports, topology_data):
        """
        Simple VLAN uniqueness validation: only check uniqueness among tracked ports

        This is the key insight: Only check for VLAN duplicates among the ports that were
        actually visited/tracked during BFS traversal, not ALL ports on the device.

        Args:
            device_name: Device name
            tracked_vlans: Set of VLAN IDs that were tracked from peer devices during BFS
            tracked_ports: Set of port names that were tracked during BFS traversal
            topology_data: Topology data
        """
        seen_vlans = {}  # vlan_id -> port_name (only for tracked VLANs on tracked ports)

        # Only check the ports that were tracked during BFS traversal
        for port_name in tracked_ports:
            port_vlans = self._get_port_vlans(device_name, port_name, topology_data)

            for vlan_id in port_vlans:
                # Only check VLANs that were tracked from peer devices
                if vlan_id in tracked_vlans:
                    if vlan_id in seen_vlans:
                        self.result.add_issue(
                            'E7003',
                            {"device": device_name, "vlan": vlan_id, "port1": seen_vlans[vlan_id], "port2": port_name}
                        )
                    else:
                        seen_vlans[vlan_id] = port_name

    def _validate_vlan_mapping(self, device_name, device_vlans, stored_vlans):
        """
        Validate that all VLAN IDs can be uniquely mapped to peer links

        Args:
            device_name: Device name
            device_vlans: Set of VLAN IDs on this device
            stored_vlans: Set of VLAN IDs stored from peer links
        """
        # Check if device VLANs match stored VLANs from peer links
        if device_vlans != stored_vlans:
            missing_vlans = device_vlans - stored_vlans
            extra_vlans = stored_vlans - device_vlans

            if missing_vlans:
                self.result.add_issue(
                    'E7004',
                    {"device": device_name, "missing": sorted(missing_vlans)}
                )

            if extra_vlans:
                self.result.add_issue(
                    'E7005',
                    {"device": device_name, "extra": sorted(extra_vlans)}
                )

    def _get_port_vlans(self, device_name, port_name, topology_data):
        """
        Get VLAN IDs configured on a specific port

        Args:
            device_name: Device name
            port_name: Port name
            topology_data: Topology data

        Returns:
            set: Set of VLAN IDs on this port
        """
        port_vlans = set()
        device_port_vlans = topology_data.get('port_vlans', {}).get(device_name, {})
        vlan_config = device_port_vlans.get(port_name, {})

        if not isinstance(vlan_config, dict):
            return port_vlans

        # Get VLANs from vlanids string
        vlanids = vlan_config.get('vlanids')
        if vlanids:
            vlan_set = self._validate_vlan_string(vlanids, device_name, port_name)
            if vlan_set:
                port_vlans.update(vlan_set)

        # Get VLANs from vlanlist array
        vlanlist = vlan_config.get('vlanlist')
        if vlanlist:
            vlan_set = self._validate_vlan_list(vlanlist, device_name, port_name)
            if vlan_set:
                port_vlans.update(vlan_set)

        return port_vlans

    def _validate_vlan_string(self, vlanids, device_name, port_name):
        """
        Validate VLAN IDs in string format (e.g., "2525-2556,3006-3061")

        Args:
            vlanids: VLAN IDs string
            device_name: Device name for error reporting
            port_name: Port name for error reporting

        Returns:
            set: Set of VLAN IDs found, or None if parsing failed
        """
        vlan_set = set()

        try:
            # Parse VLAN ranges and individual VLANs
            vlan_parts = vlanids.split(',')
            for part in vlan_parts:
                part = part.strip()
                if '-' in part:
                    # Handle range (e.g., "2525-2556")
                    range_match = re.match(r'^(\d+)-(\d+)$', part)
                    if not range_match:
                        self.result.add_issue(
                            'E7006',
                            {"device": device_name, "port": port_name, "range": part}
                        )
                        continue

                    start_vlan = int(range_match.group(1))
                    end_vlan = int(range_match.group(2))

                    if start_vlan > end_vlan:
                        self.result.add_issue(
                            'E7007',
                            {
                                "device": device_name,
                                "port": port_name,
                                "range": part,
                                "start": start_vlan,
                                "end": end_vlan
                            }
                        )
                        continue

                    # Validate each VLAN in range
                    for vlan_id in range(start_vlan, end_vlan + 1):
                        if not self._is_valid_vlan_id(vlan_id):
                            self.result.add_issue(
                                'E7008',
                                {
                                    "device": device_name,
                                    "port": port_name,
                                    "vlan": vlan_id,
                                    "min_range": self.min_vlan_id,
                                    "max_range": self.max_vlan_id
                                }
                            )
                        else:
                            vlan_set.add(vlan_id)
                else:
                    # Handle individual VLAN
                    if not part.isdigit():
                        self.result.add_issue(
                            'E7009',
                            {"device": device_name, "port": port_name, "vlan": part}
                        )
                        continue

                    vlan_id = int(part)
                    if not self._is_valid_vlan_id(vlan_id):
                        self.result.add_issue(
                            'E7008',
                            {
                                "device": device_name,
                                "port": port_name,
                                "vlan": vlan_id,
                                "min_range": self.min_vlan_id,
                                "max_range": self.max_vlan_id
                            }
                        )
                    else:
                        vlan_set.add(vlan_id)

        except ValueError as e:
            self.result.add_issue(
                'E7010',
                {
                    "device": device_name,
                    "port": port_name,
                    "vlanids": vlanids,
                    "error": str(e)
                }
            )
            return None

        return vlan_set

    def _validate_vlan_list(self, vlanlist, device_name, port_name):
        """
        Validate VLAN IDs in list format

        Args:
            vlanlist: List of VLAN IDs
            device_name: Device name for error reporting
            port_name: Port name for error reporting

        Returns:
            set: Set of VLAN IDs found, or None if validation failed
        """
        vlan_set = set()

        if not isinstance(vlanlist, list):
            self.result.add_issue(
                'E7011',
                {"device": device_name, "port": port_name, "actual_type": str(type(vlanlist))}
            )
            return None

        for i, vlan_id in enumerate(vlanlist):
            if not isinstance(vlan_id, int):
                self.result.add_issue(
                    'E7012',
                    {
                        "device": device_name,
                        "port": port_name,
                        "index": i,
                        "vlan": vlan_id,
                        "type": str(type(vlan_id))
                    }
                )
                continue

            if not self._is_valid_vlan_id(vlan_id):
                self.result.add_issue(
                    'E7008',
                    {
                        "device": device_name,
                        "port": port_name,
                        "vlan": vlan_id,
                        "min_range": self.min_vlan_id,
                        "max_range": self.max_vlan_id
                    }
                )
            else:
                vlan_set.add(vlan_id)

        return vlan_set

    def _is_valid_vlan_id(self, vlan_id):
        """
        Check if VLAN ID is in valid range

        Args:
            vlan_id: VLAN ID to validate

        Returns:
            bool: True if valid, False otherwise
        """
        return isinstance(vlan_id, int) and self.min_vlan_id <= vlan_id <= self.max_vlan_id
