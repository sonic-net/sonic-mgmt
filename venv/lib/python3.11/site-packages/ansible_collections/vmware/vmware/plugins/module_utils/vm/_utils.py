"""
Utility functions for VM configuration management.

This module provides common utility functions used across the VM configuration
system, including device node parsing and disk size conversions.
"""

import re


def parse_device_node(device_node):
    """
    Parse a device node string and return controller information.

    Device nodes specify the controller type, bus number, and unit number
    for VM devices in a standardized format. This function extracts these
    components for use in device configuration.

    Args:
        device_node (str): Device node in format "TYPE(bus:unit)"
                          Examples: "SCSI(0:0)", "SATA(1:2)", "IDE(0:1)", "NVME(0:0)"

    Returns:
        tuple: A tuple containing (controller_category, bus_number, unit_number)
               - controller_category (str): Lowercase controller category (e.g., 'scsi', 'sata')
               - bus_number (int): Controller bus number
               - unit_number (int): Device unit number on the controller

    Raises:
        ValueError: If the device node is not in the expected format

    Examples:
        SCSI(0:0) -> ('scsi', 0, 0)
        SATA(0:0) -> ('sata', 0, 0)
        IDE(0:0) -> ('ide', 0, 0)
        NVME(0:0) -> ('nvme', 0, 0)
    """
    try:
        controller_category = device_node.split("(")[0].lower()
        _device_numbers = device_node.split("(")[1].strip(")")
        controller_bus_number, controller_unit_number = _device_numbers.split(":")
        return (
            controller_category,
            int(controller_bus_number),
            int(controller_unit_number),
        )
    except (ValueError, IndexError, AttributeError):
        raise ValueError(
            "Unable to parse device node: %s. "
            "Expected format is <controller_type>(<bus_number>:<unit_number>)"
            % device_node
        )


def format_size_str_as_kb(size_str):
    """
    Convert a human-readable size string to kilobytes.

    This function parses size strings with units (kb, mb, gb, tb) and
    converts them to kilobytes for use in VMware API calls. The conversion
    uses binary units (1024-based) rather than decimal units.

    Args:
        size_str (str): Size string with unit suffix
                       Examples: "100gb", "1tb", "512mb", "1024kb"

    Returns:
        int: Size in kilobytes using binary conversion (1024-based)

    Raises:
        ValueError: If size_str is empty, has invalid format, or unsupported unit

    Examples:
        '100gb' -> 104857600
        '1tb' -> 1073741824
        '1mb' -> 1024
        '1kb' -> 1
    """
    unit_converters = {"tb": 3, "gb": 2, "mb": 1, "kb": 0}
    if not size_str:
        raise ValueError("Size string cannot be empty")

    match = re.search(r"^(\d+\.?\d*)([a-zA-Z]+)$", size_str)
    if not match:
        raise ValueError(
            "Invalid disk size format: '%s'. Format should a positive number followed by a unit abbreviation, like '100gb'."
            % size_str
        )

    disk_size_str, disk_units = match.groups()
    disk_units = disk_units.lower()

    if disk_units not in unit_converters:
        raise ValueError(
            "Unsupported size unit: '%s'. Supported units: %s"
            % (disk_units, list(unit_converters.keys()))
        )

    disk_size = float(disk_size_str)
    return int(disk_size * (1024 ** unit_converters[disk_units]))
