"""
Factory for creating platform-specific adapters.
"""

import logging
from typing import Type, Dict, Optional, Any

from .base import AdapterBase
from .qos import QoSAdapter
from .thrift import ThriftAdapter

logger = logging.getLogger(__name__)


class AdapterFactory:
    """Factory for creating platform-specific test adapters."""

    _adapters: Dict[Type[AdapterBase], Dict[str, Type[AdapterBase]]] = {
        QoSAdapter: {},
        ThriftAdapter: {},
    }

    _hwsku_prefix_map = [
        ('NH-4005', 'th5'),
        ('NH-4010', 'th5'),
        ('NH-4020', 'th5'),
        ('NH-4210', 'th6'),
        ('NH-4220', 'th6'),
        ('NH-5010', 'q3d'),
    ]

    @classmethod
    def register(cls, base_class: Type[AdapterBase], platform_name: str):
        """Decorator to register a platform-specific adapter."""
        def decorator(adapter_class: Type[AdapterBase]):
            if base_class not in cls._adapters:
                cls._adapters[base_class] = {}
            cls._adapters[base_class][platform_name] = adapter_class
            logger.debug(f"Registered {adapter_class.__name__} for platform '{platform_name}'")
            return adapter_class
        return decorator

    @classmethod
    def create_adapter(cls, adapter_type: Type[AdapterBase], duthost: Any,
                       platform_override: Optional[str] = None) -> AdapterBase:
        """Create a platform-specific adapter instance.

        Asserts if the DUT's hwsku does not match any registered adapter,
        since the adapter is what encodes the platform's expected behaviour.
        """
        platform = cls._detect_platform(duthost, platform_override)
        adapter_registry = cls._adapters.get(adapter_type, {})
        adapter_class = adapter_registry.get(platform)

        hwsku = duthost.facts.get('hwsku', '')
        # explicit raise (not assert) so the fail-loudly contract survives python -O
        if adapter_class is None:
            raise AssertionError(
                f"TAI: no {adapter_type.__name__} registered for hwsku {hwsku!r}"
            )

        logger.info(f"Creating {adapter_class.__name__} for platform '{platform}'")
        return adapter_class(duthost)

    @classmethod
    def _detect_platform(cls, duthost: Any, override: Optional[str] = None) -> Optional[str]:
        """Resolve the platform name from the DUT's hwsku prefix.

        Returns None if no prefix matches; create_adapter turns that into an
        AssertionError so an unregistered platform fails loudly.
        """
        if override:
            return override

        hwsku = duthost.facts.get('hwsku', '')
        for prefix, adapter in cls._hwsku_prefix_map:
            if hwsku.startswith(prefix):
                return adapter

        return None
