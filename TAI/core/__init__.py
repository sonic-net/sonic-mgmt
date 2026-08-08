"""
TAI Core Module

Contains base classes, factory, and facade for adapter pattern.
"""

from .base import AdapterBase
from .qos import QoSAdapter
from .thrift import ThriftAdapter
from .factory import AdapterFactory
from .facade import PlatformAdapter

__all__ = [
    'PlatformAdapter',
    'AdapterBase',
    'QoSAdapter',
    'ThriftAdapter',
    'AdapterFactory',
]
