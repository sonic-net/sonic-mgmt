"""
DeviceInfoValidator - Validates that all device info is correct within each infrastructure group.
"""

from .base_validator import GroupValidator, ValidatorContext
from .validator_factory import register_validator


@register_validator("device_info")
class DeviceInfoValidator(GroupValidator):
    """Validates that all device info is correct within each infrastructure group"""

    def __init__(self, config=None):
        super().__init__(
            name="device_info",
            description="Validates that all device info is correct within each infrastructure group",
            category="naming",
            config=config
        )

    def _validate(self, context: ValidatorContext) -> None:
        """
        Validate device info including names and HWSKU within the group

        Args:
            context: ValidatorContext containing connection graph data for a single group
        """
        # Get connection graph for this group
        conn_graph = context.get_connection_graph()
        group_name = context.get_group_name()

        # Validate all device info in a single pass
        device_count, unique_device_count = self._validate_all_devices(conn_graph, group_name)

        # Add metadata
        self.result.metadata.update({
            "total_devices": device_count,
            "group_name": group_name,
            "unique_devices": unique_device_count
        })

        if self.result.success and device_count > 0:
            self.logger.info(
                f"Device info validation summary: {device_count} devices validated in group {group_name}"
            )

    def _validate_all_devices(self, conn_graph, group_name):
        """
        Validate all device info in a single pass through the devices

        Args:
            conn_graph: Connection graph data
            group_name: Name of the current group

        Returns:
            tuple: (device_count, unique_device_count)
        """
        if 'devices' not in conn_graph:
            # missing_devices_section: No devices section found in connection graph
            self.result.add_issue(
                'E6001',
                {"group": group_name}
            )
            return 0, 0

        devices = conn_graph['devices']
        if not isinstance(devices, dict):
            # bad_devices_data_in_graph: Bad devices section data in connection graph
            self.result.add_issue(
                'E6002',
                {"group": group_name, "actual_type": type(devices).__name__}
            )
            return 0, 0

        # Get configuration options
        invalid_chars = self.config.get('invalid_chars', [])
        max_length = self.config.get('max_length', 255)

        # Track seen device names for conflict detection
        seen_names = set()
        duplicates = set()
        valid_device_names = []

        # Single pass through all devices
        for device_name, device_info in devices.items():
            # Check for empty or whitespace-only names
            if not device_name or not device_name.strip():
                # empty_device_name: Empty or whitespace-only device name
                self.result.add_issue(
                    'E6003',
                    {"group": group_name, "name": repr(device_name)}
                )
                continue

            valid_device_names.append(device_name)

            # Check for duplicate device names
            if device_name in seen_names:
                duplicates.add(device_name)
            else:
                seen_names.add(device_name)

            # Validate device name format
            self._validate_single_device_name_format(device_name, group_name, invalid_chars, max_length)

            # Validate device HwSku
            self._validate_single_device_hwsku(device_name, device_info, group_name)

        # Report all duplicate names
        for duplicate_name in duplicates:
            # conflict_device_name: Conflicting device name found
            self.result.add_issue(
                'E6004',
                {"group": group_name, "device": duplicate_name}
            )

        return len(valid_device_names), len(seen_names)

    def _validate_single_device_name_format(self, device_name, group_name, invalid_chars, max_length):
        """
        Validate format of a single device name

        Args:
            device_name: Name of the device to validate
            group_name: Name of the current group
            invalid_chars: List of invalid characters
            max_length: Maximum allowed name length
        """
        # Check for invalid characters
        found_invalid = [char for char in invalid_chars if char in device_name]
        if found_invalid:
            # invalid_characters: Device name contains invalid characters
            self.result.add_issue(
                'E6005',
                {"group": group_name, "device": device_name, "chars": found_invalid}
            )

        # Check for device names exceeding maximum length
        if len(device_name) > max_length:
            # device_name_too_long: Device name exceeds maximum length
            self.result.add_issue(
                'E6006',
                {
                    "group": group_name,
                    "device": device_name,
                    "length": len(device_name),
                    "max": max_length
                }
            )

    def _validate_single_device_hwsku(self, device_name, device_info, group_name):
        """
        Validate HwSku field for a single device

        Args:
            device_name: Name of the device
            device_info: Device information dictionary
            group_name: Name of the current group
        """
        if not isinstance(device_info, dict):
            return

        hwsku = device_info.get('HwSku', '')
        if not hwsku or not str(hwsku).strip():
            # empty_hwsku: Device has empty or missing HwSku field
            self.result.add_issue(
                'E6007',
                {"group": group_name, "device": device_name}
            )
