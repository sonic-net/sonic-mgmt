"""
TAI - Test Abstraction Interface

Platform abstraction layer for SONiC platform tests.
"""

from .core.factory import AdapterFactory
from .core.base import AdapterBase
from .core.qos import QoSAdapter
from .core.thrift import ThriftAdapter
from .core.facade import PlatformAdapter

# Import platforms to trigger adapter registration
from . import platforms  # noqa: F401

__all__ = [
    'PlatformAdapter',      # Main entry point for users
    'AdapterFactory',       # For advanced use cases
    'AdapterBase',
    'QoSAdapter',
    'ThriftAdapter',
]

__version__ = '1.0.0'
