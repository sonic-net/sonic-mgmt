"""
Reusable port attribute infrastructure for consuming transceiver
and FEC attribute hierarchies outside tests/transceiver/.
"""

__all__ = ['build_port_attributes_dict']

from .builder import build_port_attributes_dict
