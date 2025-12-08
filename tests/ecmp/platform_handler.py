"""
Platform Dependency Code (PD) - ECMP Hash Platform Handler

This module contains all platform-specific logic for ECMP hash testing.
"""

import logging
import pytest
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class ECMPHashPlatformHandler(ABC):
    """Abstract base class for platform-specific ECMP hash operations."""

    @abstractmethod
    def get_supported_skus(self):
        """Return list of supported hardware SKUs for this platform."""
        pass

    @abstractmethod
    def is_supported(self, duthost=None, hwsku=None, asic_type=None, topology=None):
        """Check if the given hardware configuration is supported.

        Args:
            duthost: DUT host object (optional, for extracting facts)
            hwsku: Hardware SKU string (optional)
            asic_type: ASIC type string (optional)
            topology: Topology name string (optional)
        """
        pass

    @abstractmethod
    def get_hash_offset_command(self, action="get", value=None):
        """Get the command to read or set hash offset value."""
        pass

    @abstractmethod
    def parse_hash_offset_output(self, output):
        """Parse the hash offset value from command output."""
        pass

    @abstractmethod
    def get_default_offset_value(self):
        """Get the default hash offset value for this platform."""
        pass


class BroadcomPlatformHandler(ECMPHashPlatformHandler):
    """Platform handler for Broadcom-based devices."""

    SUPPORTED_SKUS = [
        "Arista-7060CX-32S-C32",
        "Arista-7060CX-32S-D48C8",
        "Arista-7060CX-32S-Q32",
        "Arista-7260CX3-C64",
        "Arista-7260CX3-D108C10",
        "Arista-7260CX3-D108C8"
    ]

    DEFAULT_OFFSET = "0x1a"
    TEST_OFFSET = "0x1c"

    def get_supported_skus(self):
        """Return list of supported Broadcom hardware SKUs."""
        return self.SUPPORTED_SKUS

    def is_supported(self, duthost=None, hwsku=None, asic_type=None, topology=None):
        """Check if the given hardware configuration is supported by Broadcom platform.

        Args:
            duthost: DUT host object (optional, for extracting facts)
            hwsku: Hardware SKU string (optional)
            asic_type: ASIC type string (optional)
            topology: Topology name string (optional)
        """
        # Check ASIC type - must be Broadcom
        if asic_type and asic_type.lower() != "broadcom":
            logger.debug(f"ASIC type '{asic_type}' not supported by Broadcom platform handler")
            return False

        # Check topology - must be t0 or t1
        if topology and not any(topo in topology.lower() for topo in ["t0", "t1"]):
            logger.info(f"Topology '{topology}' not supported by Broadcom platform handler")
            return False

        # Check hardware SKU
        if hwsku and hwsku not in self.SUPPORTED_SKUS:
            logger.info(f"Hardware SKU '{hwsku}' not supported by Broadcom platform handler")
            return False

        return True

    def get_hash_offset_command(self, action="get", value=None):
        """Get the BCM command to read or set ECMP hash offset value."""
        if action == "get":
            return 'bcmcmd "sc ECMPHashSet0Offset"'
        elif action == "set" and value:
            return f'bcmcmd "sc ECMPHashSet0Offset={value}"'
        else:
            raise ValueError(f"Invalid action '{action}' or missing value for set operation")

    def parse_hash_offset_output(self, output):
        """Parse the ECMP hash offset value from BCM command output."""
        if output.get("rc") != 0:
            logger.warning("Command failed to execute successfully")
            return None

        for line in output.get("stdout_lines", []):
            if "0x" in line:
                return line.strip()
        return None

    def get_default_offset_value(self):
        """Get the default hash offset value for Broadcom platform."""
        return self.DEFAULT_OFFSET

    def get_test_offset_value(self):
        """Get the test hash offset value for Broadcom platform."""
        return self.TEST_OFFSET


class MellanoxPlatformHandler(ECMPHashPlatformHandler):
    """Platform handler for Mellanox-based devices."""

    SUPPORTED_SKUS = [
        # Add Mellanox SKUs here when supported
    ]

    def get_supported_skus(self):
        """Return list of supported Mellanox hardware SKUs."""
        return self.SUPPORTED_SKUS

    def is_supported(self, duthost=None, hwsku=None, asic_type=None, topology=None):
        """Check if the given hardware configuration is supported by Mellanox platform.

        Args:
            duthost: DUT host object (optional, for extracting facts)
            hwsku: Hardware SKU string (optional)
            asic_type: ASIC type string (optional)
            topology: Topology name string (optional)
        """
        # Check ASIC type - must be Mellanox
        if asic_type and asic_type.lower() != "mellanox":
            logger.debug(f"ASIC type '{asic_type}' not supported by Mellanox platform handler")
            return False

        # Check topology - must be t0 or t1
        if topology and not any(topo in topology.lower() for topo in ["t0", "t1"]):
            logger.info(f"Topology '{topology}' not supported by Mellanox platform handler")
            return False

        # Check if we have any supported SKUs at all - if not, Mellanox platform is not implemented yet
        if not self.SUPPORTED_SKUS:
            logger.info("Mellanox platform handler has no supported SKUs defined - platform not implemented yet")
            return False

        # Check hardware SKU
        if hwsku and hwsku not in self.SUPPORTED_SKUS:
            logger.info(f"Hardware SKU '{hwsku}' not supported by Mellanox platform handler")
            return False

        return True

    def get_hash_offset_command(self, action="get", value=None):
        """Get the Mellanox command to read or set ECMP hash offset value."""
        # TODO: Implement Mellanox-specific commands
        raise NotImplementedError("Mellanox platform support not implemented yet")

    def parse_hash_offset_output(self, output):
        """Parse the ECMP hash offset value from Mellanox command output."""
        # TODO: Implement Mellanox-specific parsing
        raise NotImplementedError("Mellanox platform support not implemented yet")

    def get_default_offset_value(self):
        """Get the default hash offset value for Mellanox platform."""
        # TODO: Implement Mellanox-specific default value
        raise NotImplementedError("Mellanox platform support not implemented yet")


class PlatformHandlerFactory:
    """Factory class to create appropriate platform handlers."""

    _handlers = {
        "broadcom": BroadcomPlatformHandler,
        "mellanox": MellanoxPlatformHandler,
    }

    @classmethod
    def get_handler(cls, platform_type):
        """Get the appropriate platform handler."""
        handler_class = cls._handlers.get(platform_type.lower())
        if not handler_class:
            raise ValueError(f"Unsupported platform type: {platform_type}")
        return handler_class()

    @classmethod
    def auto_detect_handler(cls, duthost=None, tbinfo=None):
        """Auto-detect platform handler based on hardware configuration.

        Args:
            duthost: DUT host object (optional, for extracting facts)
            tbinfo: Testbed information (optional, for extracting facts)
        """
        if isinstance(duthost, str):
            hwsku = duthost
            duthost = None

        # Extract platform info for better error messages
        if duthost and tbinfo:
            hwsku = duthost.facts.get('hwsku', 'unknown')
            asic_type = duthost.facts.get('asic_type', 'unknown')
            topo_type = tbinfo["topo"]["type"]
        else:
            asic_type = 'unknown'
            topo_type = 'unknown'

        logger.info(f"Auto-detecting platform handler for: ASIC={asic_type}, SKU={hwsku}, Topology Type={topo_type}")

        # Direct ASIC type to platform mapping for faster and more accurate detection
        asic_to_platform_map = {
            'broadcom': 'broadcom',
            'mellanox': 'mellanox'
        }

        # Try direct ASIC type mapping first
        if asic_type and asic_type.lower() in asic_to_platform_map:
            platform_name = asic_to_platform_map[asic_type.lower()]
            if platform_name in cls._handlers:
                handler_class = cls._handlers[platform_name]
                handler = handler_class()
                logger.info(f"Trying {platform_name} platform handler based on ASIC type '{asic_type}'...")
                if handler.is_supported(duthost=duthost, hwsku=hwsku, asic_type=asic_type, topology=topo_type):
                    logger.info(f"Auto-detected platform: {platform_name}")
                    return handler
                else:
                    # If the direct mapping fails, return None to skip the test
                    logger.info(
                        f"ASIC type '{asic_type}' maps to {platform_name} platform, but configuration is not supported:"
                        f"SKU={hwsku}, Topology={topo_type}. "
                        f"the HWSKU is not in the supported list or topo_type is not supported, "
                        f"or the platform is not implemented yet."
                    )
                    return None

        logger.info(f"ASIC type '{asic_type}' not in direct mapping, trying all available handlers...")

        # No platform handler found - return None to skip the test
        logger.info(
            f"No platform handler found for configuration: "
            f"ASIC={asic_type}, SKU={hwsku}, Topology={topo_type}. "
            f"Available platforms: {list(cls._handlers.keys())}"
        )
        return None

    @classmethod
    def register_handler(cls, platform_type, handler_class):
        """Register a new platform handler."""
        cls._handlers[platform_type.lower()] = handler_class


class ECMPHashManager:
    """Manager class for ECMP hash operations across different platforms."""

    def __init__(self, duthost, tbinfo=None):
        """Initialize the ECMP hash manager with a DUT host.

        Args:
            duthost: DUT host object
            tbinfo: Testbed info (optional, for topology information)
        """
        self.duthost = duthost
        self.hwsku = duthost.facts['hwsku']
        self.asic_type = duthost.facts.get('asic_type')

        # Extract topology from tbinfo if available, fallback to duthost facts
        if tbinfo:
            self.topology = tbinfo.get("topo", {}).get("name", "")
            self.topo_type = tbinfo["topo"]["type"]
        else:
            self.topology = 'unknown'
            self.topo_type = 'unknown'

        self.handler = PlatformHandlerFactory.auto_detect_handler(duthost=duthost, tbinfo=tbinfo)

        # If no handler is found, skip the test
        if self.handler is None:
            skip_msg = (
                f"ECMP hash test not supported on {duthost.hostname}: "
                f"ASIC={self.asic_type}, SKU={self.hwsku}, Topology={self.topology}, Topology Type={self.topo_type}. "
                f"Platform is either not implemented or not supported."
            )
            pytest.skip(skip_msg)

        self._original_value = None

    def is_supported(self):
        """Check if the current platform supports ECMP hash offset testing."""
        if self.handler is None:
            return False
        return self.handler.is_supported(duthost=self.duthost,
                                         hwsku=self.hwsku,
                                         asic_type=self.asic_type,
                                         topology=self.topo_type)

    def get_current_offset(self):
        """Get the current ECMP hash offset value."""
        command = self.handler.get_hash_offset_command(action="get")
        output = self.duthost.command(command, module_ignore_errors=True)
        logger.info(f"ECMP hash offset command output: {output.get('stdout_lines', [])}")
        return self.handler.parse_hash_offset_output(output)

    def set_offset(self, value):
        """Set the ECMP hash offset value."""
        command = self.handler.get_hash_offset_command(action="set", value=value)
        logger.info(f"Setting ECMP hash offset to {value}")
        return self.duthost.command(command, module_ignore_errors=True)

    def backup_current_offset(self):
        """Backup the current ECMP hash offset value."""
        self._original_value = self.get_current_offset()
        if self._original_value is None:
            logger.warning("Could not retrieve original ECMP hash offset value")
            self._original_value = self.handler.get_default_offset_value()
        logger.info(f"Backed up original ECMP hash offset: {self._original_value}")
        return self._original_value

    def restore_original_offset(self):
        """Restore the original ECMP hash offset value."""
        if self._original_value:
            logger.info(f"Restoring ECMP hash offset to {self._original_value}")
            return self.set_offset(self._original_value)
        else:
            logger.warning("No original value to restore")
            return None

    def set_test_offset(self):
        """Set the ECMP hash offset to test value."""
        if hasattr(self.handler, 'get_test_offset_value'):
            test_value = self.handler.get_test_offset_value()
            return self.set_offset(test_value)
        else:
            raise NotImplementedError("Test offset value not defined for this platform")

    def get_support_info(self):
        """Get detailed support information for debugging.

        Returns:
            dict: Dictionary with support details
        """
        return {
            "hwsku": self.hwsku,
            "asic_type": self.asic_type,
            "topology": self.topology,
            "handler_type": type(self.handler).__name__ if self.handler else "None",
            "is_supported": self.is_supported()
        }
