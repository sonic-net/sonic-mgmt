"""
PDUValidator - Validates that all DevSonic and Fanout devices have PDU connections configured
"""

from .base_validator import GlobalValidator, ValidationResult, ValidatorContext, ValidationCategory
from .validator_factory import register_validator


@register_validator("pdu")
class PDUValidator(GlobalValidator):
    """Validates that all DevSonic and Fanout devices have PDU connections configured"""

    def __init__(self, config=None):
        super().__init__(
            name="pdu",
            description="Validates that all DevSonic and Fanout devices have PDU connections configured",
            category="connectivity"
        )
        self.config = config or {}

    def _validate(self, context: ValidatorContext) -> ValidationResult:
        """
        Validate PDU connections for DevSonic and Fanout devices across all groups

        Args:
            context: ValidatorContext containing testbed and connection graph data

        Returns:
            ValidationResult: Comprehensive validation result
        """
        result = ValidationResult(validator_name=self.name, group_name="global", success=True)

        # Collect PDU connection data from all groups
        pdu_data = self._collect_pdu_data_globally(context, result)
        if not pdu_data:
            result.add_info("No PDU connection data found", ValidationCategory.SUMMARY)
            return result

        # Validate PDU connections
        validation_stats = self._validate_pdu_connections(pdu_data, result)

        # Add metadata
        result.metadata.update({
            "target_devices": validation_stats["target_devices"],
            "devices_with_pdu": validation_stats["devices_with_pdu"],
            "pdu_devices": validation_stats["pdu_devices"],
            "total_psu_connections": validation_stats["total_psu_connections"],
            "power_redundancy_warnings": validation_stats["power_redundancy_warnings"]
        })

        if result.success:
            result.add_info(
                f"PDU validation passed for {validation_stats['devices_with_pdu']} out of "
                f"{validation_stats['target_devices']} target devices with "
                f"{validation_stats['total_psu_connections']} PSU connections",
                ValidationCategory.SUMMARY, result.metadata
            )

        return result

    def _collect_pdu_data_globally(self, context: ValidatorContext, result):
        """
        Collect PDU connection data from all groups in the global context

        Args:
            context: ValidatorContext with global data
            result: ValidationResult to add issues to

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
                    result.add_warning(
                        f"Device {device_name} has PDU configuration in multiple groups",
                        ValidationCategory.DUPLICATE,
                        {"device": device_name, "groups": [group_name, "previous"]}
                    )
                all_pdu_links[device_name] = pdu_info

        if not all_target_devices:
            result.add_info("No target devices (DevSonic or Fanout*) found across all groups",
                            ValidationCategory.SUMMARY)
            return None

        return {
            'devices': all_devices,
            'pdu_links': all_pdu_links,
            'target_devices': [device for device, group in all_target_devices],
            'target_devices_with_groups': all_target_devices
        }

    def _collect_pdu_data(self, conn_graph, result):
        """
        Collect PDU connection data from the connection graph

        Args:
            conn_graph: Connection graph data
            result: ValidationResult to add issues to

        Returns:
            dict: PDU data with target devices, PDU links, and PDU devices
        """
        devices = conn_graph.get('devices', {})
        pdu_links = conn_graph.get('pdu_links', {})

        if not devices:
            result.add_error("No devices found in connection graph", ValidationCategory.MISSING_DATA)
            return None

        # Find target devices (DevSonic and Fanout*)
        target_devices = []
        for device_name, device_info in devices.items():
            if isinstance(device_info, dict):
                device_type = device_info.get('Type', '')
                if device_type == 'DevSonic' or device_type.startswith('Fanout'):
                    target_devices.append(device_name)

        if not target_devices:
            result.add_info("No target devices (DevSonic or Fanout*) found", ValidationCategory.SUMMARY)
            return None

        return {
            'devices': devices,
            'pdu_links': pdu_links,
            'target_devices': target_devices
        }

    def _validate_pdu_connections(self, pdu_data, result):
        """
        Validate PDU connections for all target devices

        Args:
            pdu_data: PDU data containing devices and connections
            result: ValidationResult to add issues to

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
                result.add_error(
                    f"Device {device_name} ({device_type}) has no PDU connections configured",
                    ValidationCategory.MISSING_DATA,
                    {"device": device_name, "device_type": device_type}
                )
                continue

            # Validate PDU connections for this device
            device_pdu_info = pdu_links[device_name]
            if not isinstance(device_pdu_info, dict):
                result.add_error(
                    f"Device {device_name} PDU connection info must be a dictionary",
                    ValidationCategory.FORMAT,
                    {"device": device_name, "pdu_info": device_pdu_info}
                )
                continue

            # Validate each PSU connection
            device_stats = self._validate_device_psu_connections(
                device_name, device_pdu_info, devices, pdu_port_usage, result
            )

            if device_stats["psu_count"] > 0:
                devices_with_pdu += 1
                total_psu_connections += device_stats["psu_count"]
                pdu_devices.update(device_stats["pdu_devices"])

                # Check power redundancy
                if device_stats["psu_count"] == 1:
                    result.add_warning(
                        f"Device {device_name} has only one PSU connection - no power redundancy",
                        ValidationCategory.CONSISTENCY_ERROR,
                        {"device": device_name, "psu_count": device_stats["psu_count"]}
                    )
                    power_redundancy_warnings += 1

        return {
            "target_devices": len(target_devices),
            "devices_with_pdu": devices_with_pdu,
            "pdu_devices": len(pdu_devices),
            "total_psu_connections": total_psu_connections,
            "power_redundancy_warnings": power_redundancy_warnings
        }

    def _validate_device_psu_connections(self, device_name, device_pdu_info, devices, pdu_port_usage, result):
        """
        Validate PSU connections for a single device

        Args:
            device_name: Name of the device
            device_pdu_info: PDU connection info for the device
            devices: All devices in the connection graph
            pdu_port_usage: Dictionary tracking PDU port usage
            result: ValidationResult to add issues to

        Returns:
            dict: Device validation statistics
        """
        psu_count = 0
        pdu_devices = set()

        for psu_name, psu_info in device_pdu_info.items():
            if not isinstance(psu_info, dict):
                result.add_error(
                    f"Device {device_name} PSU {psu_name} info must be a dictionary",
                    ValidationCategory.FORMAT,
                    {"device": device_name, "psu": psu_name, "psu_info": psu_info}
                )
                continue

            # Validate each feed for this PSU
            for feed_name, feed_info in psu_info.items():
                if not isinstance(feed_info, dict):
                    result.add_error(
                        f"Device {device_name} PSU {psu_name} feed {feed_name} info must be a dictionary",
                        ValidationCategory.FORMAT,
                        {"device": device_name, "psu": psu_name, "feed": feed_name, "feed_info": feed_info}
                    )
                    continue

                # Validate PDU connection properties
                self._validate_pdu_connection_properties(
                    device_name, psu_name, feed_name, feed_info, devices, result
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
                        result.add_error(
                            f"PDU outlet {pdu_device}:{pdu_port} is used by multiple devices: "
                            f"{existing_device_psu}, {device_psu_key}",
                            ValidationCategory.DUPLICATE,
                            {
                                "pdu_device": pdu_device,
                                "pdu_port": pdu_port,
                                "device_psu1": existing_device_psu,
                                "device_psu2": device_psu_key
                            }
                        )
                    else:
                        pdu_port_usage[port_key] = device_psu_key

            psu_count += 1

        return {
            "psu_count": psu_count,
            "pdu_devices": pdu_devices
        }

    def _validate_pdu_connection_properties(self, device_name, psu_name, feed_name, feed_info, devices, result):
        """
        Validate PDU connection properties for a single feed

        Args:
            device_name: Name of the device
            psu_name: Name of the PSU
            feed_name: Name of the power feed
            feed_info: Feed connection information
            devices: All devices in the connection graph
            result: ValidationResult to add issues to
        """
        # Validate required fields
        required_fields = ['peerdevice', 'peerport', 'feed']
        for field in required_fields:
            if field not in feed_info:
                result.add_error(
                    f"Device {device_name} PSU {psu_name} feed {feed_name} missing required field '{field}'",
                    ValidationCategory.MISSING_DATA,
                    {"device": device_name, "psu": psu_name, "feed": feed_name, "missing_field": field}
                )

        # Validate PDU device exists
        pdu_device = feed_info.get('peerdevice')
        if pdu_device:
            if pdu_device not in devices:
                result.add_error(
                    f"Device {device_name} PSU {psu_name} points to non-existent PDU {pdu_device}",
                    ValidationCategory.INVALID_FORMAT,
                    {"device": device_name, "psu": psu_name, "pdu_device": pdu_device}
                )
            else:
                # Check PDU device type
                pdu_info = devices[pdu_device]
                if isinstance(pdu_info, dict):
                    pdu_type = pdu_info.get('Type', '').lower()
                    if pdu_type != 'pdu':
                        result.add_warning(
                            f"Device {device_name} PSU {psu_name} PDU {pdu_device} has unexpected type '{pdu_type}' "
                            f"(expected 'Pdu')",
                            ValidationCategory.INVALID_TYPE,
                            {"device": device_name, "psu": psu_name, "pdu_device": pdu_device, "pdu_type": pdu_type}
                        )

        # Validate PDU port
        pdu_port = feed_info.get('peerport')
        if pdu_port and not str(pdu_port).strip():
            result.add_error(
                f"Device {device_name} PSU {psu_name} has empty PDU port",
                ValidationCategory.INVALID_FORMAT,
                {"device": device_name, "psu": psu_name}
            )

        # Validate power feed identifier
        feed_id = feed_info.get('feed')
        if feed_id:
            valid_feeds = ['A', 'B', 'N/A']
            if feed_id not in valid_feeds:
                result.add_warning(
                    f"Device {device_name} PSU {psu_name} has unusual power feed '{feed_id}' "
                    f"(expected one of: {', '.join(valid_feeds)})",
                    ValidationCategory.INVALID_FORMAT,
                    {"device": device_name, "psu": psu_name, "feed_id": feed_id, "valid_feeds": valid_feeds}
                )
