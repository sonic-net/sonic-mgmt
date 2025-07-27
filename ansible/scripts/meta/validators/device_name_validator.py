"""
DeviceNameValidator - Validates that all device names are unique within each infrastructure group.
"""

from .base_validator import GroupValidator, ValidatorContext
from .validator_factory import register_validator


@register_validator("device_name")
class DeviceNameValidator(GroupValidator):
    """Validates that all device names are unique within each infrastructure group"""

    def __init__(self, config=None):
        super().__init__(
            name="device_name",
            description="Validates that all device names are unique within each infrastructure group",
            category="naming"
        )
        self.config = config or {}

    def _validate(self, context: ValidatorContext) -> None:
        """
        Validate that device names are unique within the group

        Args:
            context: ValidatorContext containing connection graph data for a single group
        """
        # Get connection graph for this group
        conn_graph = context.get_connection_graph()

        # Extract and validate device names
        device_names = self._extract_device_names(conn_graph, context.get_group_name())

        # Check for duplicates within the group
        self._check_duplicate_device_names(device_names, context.get_group_name())

        # Validate device name format
        self._validate_device_name_format(device_names, context.get_group_name())

        # Add metadata
        self.result.metadata.update({
            "total_devices": len(device_names),
            "group_name": context.get_group_name(),
            "unique_devices": len(set(device_names)) if device_names else 0
        })

        if self.result.success and device_names:
            group_name = context.get_group_name()
            self.logger.info(
                f"Device name validation summary: {len(device_names)} devices validated in group {group_name}"
            )

    def _extract_device_names(self, conn_graph, group_name):
        """
        Extract all device names from the connection graph

        Args:
            conn_graph: Connection graph data
            group_name: Name of the current group

        Returns:
            list: List of device names
        """
        device_names = []

        if 'devices' not in conn_graph:
            self.result.add_issue(
                'E6001',
                {"group": group_name}
            )
            return device_names

        devices = conn_graph['devices']
        if not isinstance(devices, dict):
            self.result.add_issue(
                'E6002',
                {"group": group_name, "actual_type": type(devices).__name__}
            )
            return device_names

        for device_name, device_info in devices.items():
            if device_name:  # Only add non-empty device names
                device_names.append(device_name)
            else:
                self.result.add_issue(
                    'E6003',
                    {"group": group_name}
                )

        return device_names

    def _check_duplicate_device_names(self, device_names, group_name):
        """
        Check for duplicate device names within the group

        Args:
            device_names: List of device names
            group_name: Name of the current group
        """
        seen_names = set()
        duplicates = set()

        for device_name in device_names:
            if device_name in seen_names:
                duplicates.add(device_name)
            else:
                seen_names.add(device_name)

        for duplicate_name in duplicates:
            self.result.add_issue(
                'E6004',
                {"group": group_name, "device": duplicate_name}
            )

    def _validate_device_name_format(self, device_names, group_name):
        """
        Validate device name format and consistency

        Args:
            device_names: List of device names
            group_name: Name of the current group
        """
        # Get configuration options
        invalid_chars = self.config.get('invalid_chars', [])
        max_length = self.config.get('max_length', 255)

        for device_name in device_names:
            # Check for empty or whitespace-only names
            if not device_name or not device_name.strip():
                self.result.add_issue(
                    'E6005',
                    {"group": group_name, "name": repr(device_name)}
                )
                continue

            # Check for invalid characters
            found_invalid = [char for char in invalid_chars if char in device_name]

            if found_invalid:
                self.result.add_issue(
                    'E6006',
                    {"group": group_name, "device": device_name, "chars": found_invalid}
                )

            # Check for device names exceeding maximum length
            if len(device_name) > max_length:
                self.result.add_issue(
                    'E6007',
                    {
                        "group": group_name,
                        "device": device_name,
                        "length": len(device_name),
                        "max": max_length
                    }
                )
