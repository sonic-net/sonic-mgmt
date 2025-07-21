"""
ConsoleValidator - Validates that all DevSonic and Fanout devices have console connections configured
"""

from .base_validator import GlobalValidator, ValidationResult, ValidatorContext, ValidationCategory
from .validator_factory import register_validator


@register_validator("console")
class ConsoleValidator(GlobalValidator):
    """Validates that all DevSonic and Fanout devices have console connections configured"""

    def __init__(self, config=None):
        super().__init__(
            name="console",
            description="Validates that all DevSonic and Fanout devices have console connections configured",
            category="connectivity"
        )
        self.config = config or {}

    def _validate(self, context: ValidatorContext) -> ValidationResult:
        """
        Validate console connections for DevSonic and Fanout devices across all groups

        Args:
            context: ValidatorContext containing testbed and connection graph data

        Returns:
            ValidationResult: Comprehensive validation result
        """
        result = ValidationResult(validator_name=self.name, group_name="global", success=True)

        # Collect console connection data from all groups
        console_data = self._collect_console_data_globally(context, result)
        if not console_data:
            result.add_info("No console connection data found", ValidationCategory.SUMMARY)
            return result

        # Validate console connections
        validation_stats = self._validate_console_connections(console_data, result)

        # Add metadata
        result.metadata.update({
            "target_devices": validation_stats["target_devices"],
            "devices_with_console": validation_stats["devices_with_console"],
            "console_servers": validation_stats["console_servers"],
            "console_conflicts": validation_stats["console_conflicts"]
        })

        if result.success:
            result.add_info(
                f"Console validation passed for {validation_stats['devices_with_console']} out of "
                f"{validation_stats['target_devices']} target devices",
                ValidationCategory.SUMMARY, result.metadata
            )

        return result

    def _collect_console_data_globally(self, context: ValidatorContext, result):
        """
        Collect console connection data from all groups in the global context

        Args:
            context: ValidatorContext with global data
            result: ValidationResult to add issues to

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
                    result.add_warning(
                        f"Device {device_name} has console configuration in multiple groups",
                        ValidationCategory.DUPLICATE,
                        {"device": device_name, "groups": [group_name, "previous"]}
                    )
                all_console_links[device_name] = console_info

        if not all_target_devices:
            result.add_info("No target devices (DevSonic or Fanout*) found across all groups",
                            ValidationCategory.SUMMARY)
            return None

        return {
            'devices': all_devices,
            'console_links': all_console_links,
            'target_devices': [device for device, group in all_target_devices],
            'target_devices_with_groups': all_target_devices
        }

    def _collect_console_data(self, conn_graph, result):
        """
        Collect console connection data from the connection graph

        Args:
            conn_graph: Connection graph data
            result: ValidationResult to add issues to

        Returns:
            dict: Console data with target devices, console links, and console servers
        """
        devices = conn_graph.get('devices', {})
        console_links = conn_graph.get('console_links', {})

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
            'console_links': console_links,
            'target_devices': target_devices
        }

    def _validate_console_connections(self, console_data, result):
        """
        Validate console connections for all target devices

        Args:
            console_data: Console data containing devices and connections
            result: ValidationResult to add issues to

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
                result.add_error(
                    f"Device {device_name} ({device_type}) has no console connection configured",
                    ValidationCategory.MISSING_DATA,
                    {"device": device_name, "device_type": device_type}
                )
                continue

            # Validate console connection properties
            console_info = console_links[device_name]
            if not isinstance(console_info, dict):
                result.add_error(
                    f"Device {device_name} console connection info must be a dictionary",
                    ValidationCategory.FORMAT,
                    {"device": device_name, "console_info": console_info}
                )
                continue

            # Check for ConsolePort entry
            console_port_info = console_info.get('ConsolePort')
            if not console_port_info:
                result.add_error(
                    f"Device {device_name} console connection missing ConsolePort information",
                    ValidationCategory.MISSING_DATA,
                    {"device": device_name}
                )
                continue

            # Validate console port properties
            self._validate_console_port_properties(device_name, console_port_info, devices, result)

            # Track console port usage for conflict detection
            console_server = console_port_info.get('peerdevice')
            console_port = console_port_info.get('peerport')

            if console_server and console_port:
                console_servers.add(console_server)
                port_key = (console_server, console_port)

                if port_key in console_port_usage:
                    # Console port conflict detected
                    existing_device = console_port_usage[port_key]
                    result.add_error(
                        f"Console port {console_server}:{console_port} is used by multiple devices: "
                        f"{existing_device}, {device_name}",
                        ValidationCategory.DUPLICATE,
                        {
                            "console_server": console_server,
                            "console_port": console_port,
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

    def _validate_console_port_properties(self, device_name, console_port_info, devices, result):
        """
        Validate console port connection properties

        Args:
            device_name: Name of the device
            console_port_info: Console port information dictionary
            devices: All devices in the connection graph
            result: ValidationResult to add issues to
        """
        if not isinstance(console_port_info, dict):
            result.add_error(
                f"Device {device_name} ConsolePort info must be a dictionary",
                ValidationCategory.FORMAT,
                {"device": device_name, "console_port_info": console_port_info}
            )
            return

        # Validate required fields
        required_fields = ['peerdevice', 'peerport']
        for field in required_fields:
            if field not in console_port_info:
                result.add_error(
                    f"Device {device_name} console connection missing required field '{field}'",
                    ValidationCategory.MISSING_DATA,
                    {"device": device_name, "missing_field": field}
                )

        # Validate console server exists
        console_server = console_port_info.get('peerdevice')
        if console_server:
            if console_server not in devices:
                result.add_error(
                    f"Device {device_name} console points to non-existent server {console_server}",
                    ValidationCategory.INVALID_FORMAT,
                    {"device": device_name, "console_server": console_server}
                )
            else:
                # Check console server type
                server_info = devices[console_server]
                if isinstance(server_info, dict):
                    server_type = server_info.get('Type', '').lower()
                    if server_type not in ['consoleserver']:
                        result.add_warning(
                            f"Device {device_name} console server {console_server} has unexpected type '{server_type}'",
                            ValidationCategory.INVALID_TYPE,
                            {"device": device_name, "console_server": console_server, "server_type": server_type}
                        )

        # Validate console port
        console_port = console_port_info.get('peerport')
        if console_port and not str(console_port).strip():
            result.add_error(
                f"Device {device_name} console connection has empty console port",
                ValidationCategory.INVALID_FORMAT,
                {"device": device_name}
            )

        # Validate optional fields exist but don't require specific values
        optional_fields = ['proxy', 'type', 'menu_type', 'baud_rate']
        for field in optional_fields:
            if field in console_port_info:
                value = console_port_info[field]
                if value is None or (isinstance(value, str) and not value.strip()):
                    result.add_warning(
                        f"Device {device_name} console connection has empty {field}",
                        ValidationCategory.INVALID_FORMAT,
                        {"device": device_name, "field": field}
                    )
