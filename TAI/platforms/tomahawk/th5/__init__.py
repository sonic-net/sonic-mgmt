"""
TH5 (Tomahawk 5) platform adapters.

First of the Tomahawk generation — base class for subsequent TH generations.
"""

from .qos import TH5QoSAdapter
from .thrift import TH5ThriftAdapter

__all__ = ['TH5QoSAdapter', 'TH5ThriftAdapter']
