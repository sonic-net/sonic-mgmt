"""
Abstract base classes for VM configuration services.

This module provides the base class that all VM configuration services
should inherit from to ensure consistent interfaces.

Currently, this module is empty but may be extended in the future.
"""

from abc import ABC, abstractmethod


class AbstractService(ABC):
    @abstractmethod
    def __init__(self):
        pass
