"""
PDUValidator - Validates that all DevSonic and Fanout devices have PDU connections configured
"""

import re
from .base_validator import GlobalValidator, ValidatorContext
from .validator_factory import register_validator


@register_validator("pdu")
class PDUValidator(GlobalValidator):
    """Validates that all DevSonic and Fanout devices have PDU connections configured"""

    def __init__(self, config=None):
        super().__init__(
            name="pdu",
            description="Validates that all DevSonic and Fanout devices have PDU connections configured",
            category="connectivity",
            config=config
        )
        self.exclude_devices = self.config.get('exclude_devices', [])

    def _is_device_excluded(self, device_name):
        """
        Check if a device should be excluded from validation based on regex patterns

        Args:
            device_name: Name of the device to check

        Returns:
            bool: True if device should be excluded, False otherwise
        """
        for pattern in self.exclude_devices:
            try:
                if re.match(pattern, device_name):
                    return True
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern '{pattern}' in exclude_devices: {e}")
        return False

    def _validate(self, context: ValidatorContext) -> None:
        """
        Validate PDU connections for DevSonic and Fanout devices across all groups

        Args:
            context: ValidatorContext containing testbed and connection graph data
        """

        # Collect PDU connection data from all groups
        pdu_data = self._collect_pdu_data_globally(context)
        if not pdu_data:
            self.logger.info("PDU validation summary: No PDU connection data found")
            return

        # Validate PDU connections
        validation_stats = self._validate_pdu_connections(pdu_data)

        # Add metadata
        self.result.metadata.update({
            "target_devices": validation_stats["target_devices"],
            "devices_with_pdu": validation_stats["devices_with_pdu"],
            "pdu_devices": validation_stats["pdu_devices"],
            "total_psu_connections": validation_stats["total_psu_connections"],
            "power_redundancy_warnings": validation_stats["power_redundancy_warnings"]
        })

        if self.result.success:
            devices_with_pdu = validation_stats['devices_with_pdu']
            target_devices = validation_stats['target_devices']
            total_psu_connections = validation_stats['total_psu_connections']
            self.logger.info(
                f"PDU validation summary: {devices_with_pdu} of {target_devices} target devices have PDU connections, "
                f"{total_psu_connections} total PSU connections"
            )

    def _collect_pdu_data_globally(self, context: ValidatorContext):
        """
        Collect PDU connection data from all groups in the global context

        Args:
            context: ValidatorContext with global data

        Returns:
            dict: PDU data with target devices, PDU links, and PDU devices from all groups
        """
        all_target_devices = []
        all_pdu_links = {}
        all_devices = {}

        # Collect data from all groups
        all_conn_graphs = context.get_all_connection_graphs()

        for group_name, conn_graph in all_conn_graphs.items():
            if not conn_graph:
                continue

            devices = conn_graph.get('devices', {})
            pdu_links = conn_graph.get('pdu_links', {})

            # Find target devices (DevSonic and Fanout*) in this group
            for device_name, device_info in devices.items():
                if isinstance(device_info, dict):
                    device_type = device_info.get('Type', '')
                    if device_type == 'DevSonic' or device_type.startswith('Fanout'):
                        # Check if device should be excluded
                        if not self._is_device_excluded(device_name):
                            all_target_devices.append((device_name, group_name))

            # Add all devices and PDU links (with group info for debugging)
            for device_name, device_info in devices.items():
                if device_name in all_devices:
                    # Device exists in multiple groups - this could be expected
                    pass
                else:
                    all_devices[device_name] = device_info

            # Add PDU links
            for device_name, pdu_info in pdu_links.items():
                if device_name in all_pdu_links:
                    # PDU link exists in multiple groups - could indicate duplicate config
                    # duplicate_config_groups: Device has PDU configuration in multiple groups
                    self.result.add_issue(
                        'E4001',
                        {"device": device_name, "group": group_name}
                    )
                all_pdu_links[device_name] = pdu_info

        if not all_target_devices:
            self.logger.info("PDU validation summary: No target devices (DevSonic or Fanout*) found across all groups")
            return None

        return {
            'devices': all_devices,
            'pdu_links': all_pdu_links,
            'target_devices': [device for device, group in all_target_devices],
            'target_devices_with_groups': all_target_devices
        }

    def _validate_pdu_connections(self, pdu_data):
        """
        Validate PDU connections for all target devices

        Args:
            pdu_data: PDU data containing devices and connections

        Returns:
            dict: Validation statistics
        """
        target_devices = pdu_data['target_devices']
        pdu_links = pdu_data['pdu_links']
        devices = pdu_data['devices']

        devices_with_pdu = 0
        pdu_devices = set()
        total_psu_connections = 0
        power_redundancy_warnings = 0
        pdu_port_usage = {}  # (pdu_device, pdu_port) -> device_name:psu_name

        for device_name in target_devices:
            device_type = devices[device_name].get('Type', '')

            # Check if device has PDU connections
            if device_name not in pdu_links:
                # missing_pdu: Device has no PDU connections configured
                self.result.add_issue(
                    'E4002',
                    {"device": device_name, "device_type": device_type}
                )
                continue

            # Validate PDU connections for this device
            device_pdu_info = pdu_links[device_name]
            if not isinstance(device_pdu_info, dict):
                # bad_pdu_data_in_graph: Bad PDU connection data in connection graph
                self.result.add_issue(
                    'E4003',
                    {"device": device_name, "actual_type": type(device_pdu_info).__name__}
                )
                continue

            # Validate each PSU connection
            device_stats = self._validate_device_psu_connections(
                device_name, device_pdu_info, devices, pdu_port_usage
            )

            if device_stats["psu_count"] > 0:
                devices_with_pdu += 1
                total_psu_connections += device_stats["psu_count"]
                pdu_devices.update(device_stats["pdu_devices"])

                # Check power redundancy
                if device_stats["psu_count"] == 1:
                    # no_power_redundancy: Device has only one PSU connection - no power redundancy
                    self.result.add_issue(
                        'E4004',
                        {"device": device_name, "psu_count": device_stats['psu_count']}
                    )
                    power_redundancy_warnings += 1

        return {
            "target_devices": len(target_devices),
            "devices_with_pdu": devices_with_pdu,
            "pdu_devices": len(pdu_devices),
            "total_psu_connections": total_psu_connections,
            "power_redundancy_warnings": power_redundancy_warnings
        }

    def _validate_device_psu_connections(self, device_name, device_pdu_info, devices, pdu_port_usage):
        """
        Validate PSU connections for a single device

        Args:
            device_name: Name of the device
            device_pdu_info: PDU connection info for the device
            devices: All devices in the connection graph
            pdu_port_usage: Dictionary tracking PDU port usage

        Returns:
            dict: Device validation statistics
        """
        psu_count = 0
        pdu_devices = set()

        for psu_name, psu_info in device_pdu_info.items():
            if not isinstance(psu_info, dict):
                # bad_psu_data_in_graph: Bad PSU configuration data in connection graph
                self.result.add_issue(
                    'E4005',
                    {"device": device_name, "psu": psu_name, "actual_type": type(psu_info).__name__}
                )
                continue

            # Validate each feed for this PSU
            for feed_name, feed_info in psu_info.items():
                if not isinstance(feed_info, dict):
                    # bad_feed_data_in_graph: Bad feed configuration data in connection graph
                    self.result.add_issue(
                        'E4006',
                        {
                            "device": device_name, "psu": psu_name, "feed": feed_name,
                            "actual_type": type(feed_info).__name__
                        }
                    )
                    continue

                # Validate PDU connection properties
                self._validate_pdu_connection_properties(
                    device_name, psu_name, feed_name, feed_info, devices
                )

                # Track PDU port usage for conflict detection
                pdu_device = feed_info.get('peerdevice')
                pdu_port = feed_info.get('peerport')

                if pdu_device and pdu_port:
                    pdu_devices.add(pdu_device)
                    port_key = (pdu_device, pdu_port)
                    device_psu_key = f"{device_name}:{psu_name}"

                    if port_key in pdu_port_usage:
                        # PDU port conflict detected
                        existing_device_psu = pdu_port_usage[port_key]
                        # pdu_port_conflict: PDU outlet is used by multiple devices
                        self.result.add_issue(
                            'E4007',
                            {
                                "pdu": pdu_device,
                                "port": pdu_port,
                                "device1": existing_device_psu,
                                "device2": device_psu_key
                            }
                        )
                    else:
                        pdu_port_usage[port_key] = device_psu_key

            psu_count += 1

        return {
            "psu_count": psu_count,
            "pdu_devices": pdu_devices
        }

    def _validate_pdu_connection_properties(self, device_name, psu_name, feed_name, feed_info, devices):
        """
        Validate PDU connection properties for a single feed

        Args:
            device_name: Name of the device
            psu_name: Name of the PSU
            feed_name: Name of the power feed
            feed_info: Feed connection information
            devices: All devices in the connection graph
        """
        # Validate required fields
        required_fields = ['peerdevice', 'peerport', 'feed']
        for field in required_fields:
            if field not in feed_info:
                # missing_required_field: PDU connection missing required field
                self.result.add_issue(
                    'E4008',
                    {"device": device_name, "psu": psu_name, "feed": feed_name, "field": field}
                )

        # Validate PDU device exists
        pdu_device = feed_info.get('peerdevice')
        if pdu_device:
            if pdu_device not in devices:
                # invalid_pdu_device: PDU points to non-existent device
                self.result.add_issue(
                    'E4009',
                    {"device": device_name, "psu": psu_name, "pdu": pdu_device}
                )
            else:
                # Check PDU device type
                pdu_info = devices[pdu_device]
                if isinstance(pdu_info, dict):
                    pdu_type = pdu_info.get('Type', '').lower()
                    if pdu_type != 'pdu':
                        # invalid_pdu_type: PDU device has unexpected type
                        self.result.add_issue(
                            'E4010',
                            {
                                "device": device_name,
                                "psu": psu_name,
                                "pdu": pdu_device,
                                "type": pdu_type,
                                "expected": "pdu"
                            }
                        )

        # Validate PDU port
        pdu_port = feed_info.get('peerport')
        if pdu_port and not str(pdu_port).strip():
            # empty_pdu_port: PDU connection has empty port
            self.result.add_issue(
                'E4011',
                {"device": device_name, "psu": psu_name}
            )

        # Validate power feed identifier
        feed_id = feed_info.get('feed')
        if feed_id:
            valid_feeds = ['A', 'B', 'N/A']
            if feed_id not in valid_feeds:
                # invalid_feed_id: PDU feed ID is not valid
                self.result.add_issue(
                    'E4012',
                    {"device": device_name, "psu": psu_name, "feed_id": feed_id, "valid_feeds": valid_feeds}
                )
