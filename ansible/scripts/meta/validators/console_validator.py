"""
ConsoleValidator - Validates that all DevSonic and Fanout devices have console connections configured
"""

import re
from .base_validator import GlobalValidator, ValidatorContext
from .validator_factory import register_validator


@register_validator("console")
class ConsoleValidator(GlobalValidator):
    """Validates that all DevSonic and Fanout devices have console connections configured"""

    def __init__(self, config=None):
        super().__init__(
            name="console",
            description="Validates that all DevSonic and Fanout devices have console connections configured",
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
        Validate console connections for DevSonic and Fanout devices across all groups

        Args:
            context: ValidatorContext containing testbed and connection graph data
        """

        # Collect console connection data from all groups
        console_data = self._collect_console_data_globally(context)
        if not console_data:
            self.logger.info("Console validation summary: No console connection data found")
            return

        # Validate console connections
        validation_stats = self._validate_console_connections(console_data)

        # Add metadata
        self.result.metadata.update({
            "target_devices": validation_stats["target_devices"],
            "devices_with_console": validation_stats["devices_with_console"],
            "console_servers": validation_stats["console_servers"],
            "console_conflicts": validation_stats["console_conflicts"]
        })

        if self.result.success:
            self.logger.info(
                f"Console validation summary: {validation_stats['devices_with_console']} of "
                f"{validation_stats['target_devices']} target devices have console connections"
            )

    def _collect_console_data_globally(self, context: ValidatorContext):
        """
        Collect console connection data from all groups in the global context

        Args:
            context: ValidatorContext with global data

        Returns:
            dict: Console data with target devices, console links, and console servers from all groups
        """
        all_target_devices = []
        all_console_links = {}
        all_devices = {}

        # Collect data from all groups
        all_conn_graphs = context.get_all_connection_graphs()

        for group_name, conn_graph in all_conn_graphs.items():
            if not conn_graph:
                continue

            devices = conn_graph.get('devices', {})
            console_links = conn_graph.get('console_links', {})

            # Find target devices (DevSonic and Fanout*) in this group
            for device_name, device_info in devices.items():
                if isinstance(device_info, dict):
                    device_type = device_info.get('Type', '')
                    if device_type == 'DevSonic' or device_type.startswith('Fanout'):
                        # Check if device should be excluded
                        if not self._is_device_excluded(device_name):
                            all_target_devices.append((device_name, group_name))

            # Add all devices and console links (with group info for debugging)
            for device_name, device_info in devices.items():
                if device_name in all_devices:
                    # Device exists in multiple groups - this could be expected
                    pass
                else:
                    all_devices[device_name] = device_info

            # Add console links
            for device_name, console_info in console_links.items():
                if device_name in all_console_links:
                    # Console link exists in multiple groups - could indicate duplicate config
                    # duplicate_config_groups: Device has console configuration in multiple groups
                    self.result.add_issue(
                        'E3001',
                        {"device": device_name, "group": group_name}
                    )
                all_console_links[device_name] = console_info

        if not all_target_devices:
            self.logger.info("Console validation summary: No target devices found across all groups")
            return None

        return {
            'devices': all_devices,
            'console_links': all_console_links,
            'target_devices': [device for device, group in all_target_devices],
            'target_devices_with_groups': all_target_devices
        }

    def _validate_console_connections(self, console_data):
        """
        Validate console connections for all target devices

        Args:
            console_data: Console data containing devices and connections

        Returns:
            dict: Validation statistics
        """
        target_devices = console_data['target_devices']
        console_links = console_data['console_links']
        devices = console_data['devices']

        devices_with_console = 0
        console_servers = set()
        console_port_usage = {}  # (console_server, console_port) -> device_name

        for device_name in target_devices:
            device_type = devices[device_name].get('Type', '')

            # Check if device has console connection
            if device_name not in console_links:
                # missing_console: Device has no console connection configured
                self.result.add_issue(
                    'E3002',
                    {"device": device_name, "device_type": device_type}
                )
                continue

            # Validate console connection properties
            console_info = console_links[device_name]
            if not isinstance(console_info, dict):
                # bad_console_data_in_graph: Bad console connection data in connection graph
                self.result.add_issue(
                    'E3003',
                    {"device": device_name, "actual_type": type(console_info).__name__}
                )
                continue

            # Check for ConsolePort entry
            console_port_info = console_info.get('ConsolePort')
            if not console_port_info:
                # missing_console_port: Console connection missing ConsolePort information
                self.result.add_issue(
                    'E3004',
                    {"device": device_name}
                )
                continue

            # Validate console port properties
            self._validate_console_port_properties(device_name, console_port_info, devices)

            # Track console port usage for conflict detection
            console_server = console_port_info.get('peerdevice')
            console_port = console_port_info.get('peerport')

            if console_server and console_port:
                console_servers.add(console_server)
                port_key = (console_server, console_port)

                if port_key in console_port_usage:
                    # Console port conflict detected
                    existing_device = console_port_usage[port_key]
                    # console_port_conflict: Console port is used by multiple devices
                    self.result.add_issue(
                        'E3005',
                        {
                            "server": console_server,
                            "port": console_port,
                            "device1": existing_device,
                            "device2": device_name
                        }
                    )
                else:
                    console_port_usage[port_key] = device_name

            devices_with_console += 1

        return {
            "target_devices": len(target_devices),
            "devices_with_console": devices_with_console,
            "console_servers": len(console_servers),
            "console_conflicts": len([k for k, v in console_port_usage.items() if
                                     len([d for d in console_port_usage.values() if d == v]) > 1])
        }

    def _validate_console_port_properties(self, device_name, console_port_info, devices):
        """
        Validate console port connection properties

        Args:
            device_name: Name of the device
            console_port_info: Console port information dictionary
            devices: All devices in the connection graph
        """
        if not isinstance(console_port_info, dict):
            # bad_console_data_in_graph: Bad console connection data in connection graph
            self.result.add_issue(
                'E3003',
                {"device": device_name, "actual_type": type(console_port_info).__name__}
            )
            return

        # Validate required fields
        required_fields = ['peerdevice', 'peerport']
        for field in required_fields:
            if field not in console_port_info:
                # missing_required_field: Console connection missing required field
                self.result.add_issue(
                    'E3006',
                    {"device": device_name, "field": field}
                )

        # Validate console server exists
        console_server = console_port_info.get('peerdevice')
        if console_server:
            if console_server not in devices:
                # invalid_console_server: Console points to non-existent server
                self.result.add_issue(
                    'E3007',
                    {"device": device_name, "server": console_server}
                )
            else:
                # Check console server type
                server_info = devices[console_server]
                if isinstance(server_info, dict):
                    server_type = server_info.get('Type', '').lower()
                    if server_type not in ['consoleserver']:
                        # invalid_server_type: Console server has unexpected type
                        self.result.add_issue(
                            'E3008',
                            {
                                "device": device_name,
                                "server": console_server,
                                "type": server_type,
                                "expected": "consoleserver"
                            }
                        )

        # Validate console port
        console_port = console_port_info.get('peerport')
        if console_port and not str(console_port).strip():
            # empty_console_port: Console connection has empty port
            self.result.add_issue(
                'E3009',
                {"device": device_name}
            )

        # Validate optional fields exist but don't require specific values
        optional_fields = ['proxy', 'type', 'menu_type', 'baud_rate']
        for field in optional_fields:
            if field in console_port_info:
                value = console_port_info[field]
                if value is None or (isinstance(value, str) and not value.strip()):
                    # empty_optional_field: Console connection has empty optional field
                    self.result.add_issue(
                        'E3010',
                        {"device": device_name, "field": field}
                    )
