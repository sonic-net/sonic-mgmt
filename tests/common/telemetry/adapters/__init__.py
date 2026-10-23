"""
Telemetry adapters for SONiC test workflows.

This package provides transport-agnostic access to SONiC operational state
(interface counters, queue stats, etc.) via gNMI with CLI fallback.

Usage::

    from tests.common.telemetry.adapters import SonicTelemetryAdapter, AdapterTransport

    adapter = SonicTelemetryAdapter(duthost, ptfhost=ptfhost)
    counters = adapter.get_interface_counters("Ethernet0")
    print(counters.RX_OK, counters.TX_OK)
"""

from .base_adapter import BaseAdapter, AdapterTransport, InterfaceCounters, QueueCounters
from .gnmi_adapter import GNMIAdapter
from .cli_adapter import CLIAdapter
from .sonic_telemetry_adapter import SonicTelemetryAdapter

__all__ = [
    "BaseAdapter",
    "AdapterTransport",
    "InterfaceCounters",
    "QueueCounters",
    "GNMIAdapter",
    "CLIAdapter",
    "SonicTelemetryAdapter",
]
