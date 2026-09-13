"""
Abstract base adapter interface for SONiC telemetry access.

This module defines the contract every adapter must implement, plus the shared
dataclasses (InterfaceCounters, QueueCounters) and the AdapterTransport enum.

Field naming for InterfaceCounters deliberately mirrors the output of
``portstat -j`` so that existing test helpers that already parse that JSON
require zero changes when switching to the adapter.
"""

import enum
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class AdapterTransport(enum.Enum):
    """Which transport the adapter should use when fetching data."""

    GNMI = "gnmi"
    """Always use gNMI; raise if the service is unreachable."""

    CLI = "cli"
    """Always use SSH + CLI; never attempt gNMI."""

    AUTO = "auto"
    """Try gNMI first; silently fall back to CLI on any failure."""


@dataclass
class InterfaceCounters:
    """
    Interface counter snapshot.

    Field names match ``portstat -j`` output for drop-in compatibility:
        RX_OK, TX_OK  — total good frames (ucast + mcast + bcast)
        RX_ERR, TX_ERR — error frames
        RX_DRP, TX_DRP — dropped frames
        RX_BPS, TX_BPS — cumulative bytes (NOT a rate; see note below)
        RX_UTIL, TX_UTIL — utilisation percent (0 if port speed unavailable)
        RX_OVR, TX_OVR — overrun frames (always 0 via gNMI; see gap analysis)

    NOTE: BPS fields carry **cumulative byte counts**, not bit-per-second rates.
    Callers that need a rate must sample twice and compute:
        bps = (bytes2 - bytes1) / (t2 - t1) * 8
    """

    RX_OK: int = 0
    TX_OK: int = 0
    RX_ERR: int = 0
    TX_ERR: int = 0
    RX_DRP: int = 0
    TX_DRP: int = 0
    RX_BPS: float = 0.0
    TX_BPS: float = 0.0
    RX_UTIL: float = 0.0
    TX_UTIL: float = 0.0
    RX_OVR: int = 0
    TX_OVR: int = 0
    transport_used: Optional[AdapterTransport] = field(default=None, repr=False)


@dataclass
class QueueCounters:
    """
    Per-queue counter snapshot for a single interface.

    ``stats`` is keyed by canonical queue-counter names returned by
    ``sonic-db-cli COUNTERS_DB HGETALL COUNTERS:<oid>``, e.g.::

        {
            "UC0_PKTS": 1000,
            "UC0_BYTES": 1500000,
            "UC0_DROP_PKTS": 0,
            "UC0_DROP_BYTES": 0,
            ...
        }
    """

    stats: Dict[str, int] = field(default_factory=dict)
    transport_used: Optional[AdapterTransport] = field(default=None, repr=False)


class BaseAdapter(ABC):
    """
    Transport-agnostic interface for reading SONiC operational counters.

    Concrete implementations (GNMIAdapter, CLIAdapter) provide the
    actual data-retrieval logic.  SonicTelemetryAdapter composes them
    behind an AUTO transport that tries gNMI first.
    """

    @abstractmethod
    def is_available(self) -> bool:
        """
        Return True if this adapter can be used on the current DUT.

        For GNMIAdapter this probes whether the gNMI server is listening.
        For CLIAdapter this always returns True (SSH always works).
        """

    @abstractmethod
    def get_interface_counters(self, interface: str) -> InterfaceCounters:
        """
        Return a snapshot of counters for *interface* (e.g. ``"Ethernet0"``).

        Raises:
            RuntimeError: if the adapter cannot retrieve data.
        """

    @abstractmethod
    def get_all_interface_counters(self) -> Dict[str, InterfaceCounters]:
        """
        Return counters for every front-panel interface on the DUT.

        Returns:
            dict mapping interface name → InterfaceCounters
        """

    @abstractmethod
    def get_queue_stats(self, interface: str) -> QueueCounters:
        """
        Return per-queue counters for *interface*.

        Raises:
            RuntimeError: if the adapter cannot retrieve data.
        """

    @abstractmethod
    def clear_interface_counters(self) -> None:
        """Reset interface counters on the DUT (best-effort)."""
