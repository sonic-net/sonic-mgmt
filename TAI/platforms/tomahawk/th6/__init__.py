"""
TH6 (Tomahawk 6) platform adapters.

Inherits TH5 behaviour; override only what diverges in TH6.
"""

from .qos import TH6QoSAdapter
from .thrift import TH6ThriftAdapter

__all__ = ['TH6QoSAdapter', 'TH6ThriftAdapter']
