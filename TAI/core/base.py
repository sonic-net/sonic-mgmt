"""
Base adapter class for TAI framework.

Defines the root interface that all platform-specific adapters must implement.
"""

from abc import ABC
from typing import Any, Dict, Set
import logging

logger = logging.getLogger(__name__)


class AdapterBase(ABC):
    """
    Base class for all platform test adapters.

    Attributes:
        platform_name: Identifier for the platform (e.g., 'tomahawk', 'qumran')
        duthost: The DUT host object
        supported_features: Set of feature names this adapter supports
    """

    # Platform identifier - must be set by subclasses
    platform_name: str = 'base'

    # Supported features - must be set by subclasses
    # List all feature names that this platform adapter implements
    supported_features: Set[str] = set()

    def __init__(self, duthost):
        """
        Initialize the adapter.

        Args:
            duthost: The DUT host object containing platform facts
        """
        self.duthost = duthost
        self.platform = duthost.facts.get('platform', 'unknown')
        self.asic_type = duthost.facts.get('asic_type', 'unknown')
        self.hwsku = duthost.facts.get('hwsku', 'unknown')
        logger.info(f"Initialized {self.__class__.__name__} for platform: {self.platform}")

    def get_supported_features(self) -> Set[str]:
        """
        Get set of features supported by this adapter.

        Returns:
            Set of feature names that this adapter implements

        Example:
            features = adapter.get_supported_features()
            # {'discover_queue_key', 'apply_scheduler', 'get_interface_drop_count'}
        """
        return self.supported_features.copy()

    def get_platform_info(self) -> Dict[str, Any]:
        """
        Get platform information.

        Returns:
            Dictionary containing platform details
        """
        return {
            'platform': self.platform,
            'asic_type': self.asic_type,
            'hwsku': self.hwsku,
            'adapter': self.__class__.__name__,
            'supported_features': list(self.supported_features),
        }
