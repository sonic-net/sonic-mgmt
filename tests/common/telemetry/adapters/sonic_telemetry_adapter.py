"""
SonicTelemetryAdapter — test-facing façade over gNMI + CLI transports.

This is the entry point for test code.  It composes GNMIAdapter and
CLIAdapter behind a single, stable API and implements the AUTO transport:

    * Try gNMI first (probe availability once, then use it for all calls).
    * On ANY gNMI failure (unavailable OR runtime error) silently retry the
      same call with CLIAdapter.
    * Honour explicit transport overrides (GNMI / CLI) without fallback.

Typical usage in a test
-----------------------
::

    from tests.common.telemetry.adapters import SonicTelemetryAdapter

    def test_interface_counters(duthosts, rand_one_dut_hostname, ptfhost):
        duthost = duthosts[rand_one_dut_hostname]
        adapter = SonicTelemetryAdapter(duthost, ptfhost=ptfhost)

        # gNMI if available, CLI otherwise — completely transparent
        counters = adapter.get_interface_counters("Ethernet0")
        assert counters.RX_OK >= 0
        assert counters.TX_OK >= 0

"""

import logging
from typing import Dict, Optional

from .base_adapter import BaseAdapter, AdapterTransport, InterfaceCounters, QueueCounters
from .gnmi_adapter import GNMIAdapter
from .cli_adapter import CLIAdapter

logger = logging.getLogger(__name__)


class SonicTelemetryAdapter(BaseAdapter):
    """
    Transport-agnostic façade for SONiC operational counters.

    Args:
        duthost: ansible module handle for the DUT.
        ptfhost: ansible module handle for the PTF container (required when
                 transport is GNMI or AUTO; optional for CLI-only use).
        transport: :class:`AdapterTransport` override.  Defaults to AUTO.
    """

    def __init__(self, duthost, ptfhost=None, transport: AdapterTransport = AdapterTransport.AUTO):
        self._dut = duthost
        self._ptf = ptfhost
        self._transport = transport
        self._cli = CLIAdapter(duthost)
        self._gnmi: Optional[GNMIAdapter] = (
            GNMIAdapter(duthost, ptfhost) if ptfhost is not None else None
        )
        # Cached result of the one-time availability probe
        self._gnmi_available: Optional[bool] = None

    # Availability

    def is_available(self) -> bool:
        """Always True: CLIAdapter guarantees fallback availability."""
        return True

    # Public API (delegates to the selected transport)

    def get_interface_counters(self, interface: str) -> InterfaceCounters:
        """Return a single-interface counter snapshot."""
        return self._call(lambda a: a.get_interface_counters(interface))

    def get_all_interface_counters(self) -> Dict[str, InterfaceCounters]:
        """Return counters for every front-panel interface."""
        return self._call(lambda a: a.get_all_interface_counters())

    def get_queue_stats(self, interface: str) -> QueueCounters:
        """Return per-queue counters for *interface*."""
        return self._call(lambda a: a.get_queue_stats(interface))

    def clear_interface_counters(self) -> None:
        """Reset counters.  Always executed via CLIAdapter (gNMI has no clear RPC)."""
        self._cli.clear_interface_counters()

    # Transport selection

    def _call(self, fn):
        """
        Execute *fn(adapter)* using the configured transport strategy.

        AUTO: try gNMI once (with availability probe); fall back to CLI.
        GNMI: use gNMI only; raise on failure.
        CLI:  use CLI only.
        """
        if self._transport == AdapterTransport.CLI:
            return fn(self._cli)

        if self._transport == AdapterTransport.GNMI:
            if self._gnmi is None:
                raise RuntimeError(
                    "AdapterTransport.GNMI requested but ptfhost was not provided "
                    "to SonicTelemetryAdapter."
                )
            return fn(self._gnmi)

        # AUTO try gNMI, fall back to CLI
        return self._auto_call(fn)

    def _auto_call(self, fn):
        """Try gNMI; on any error fall back to CLI and log a warning."""
        if self._gnmi is not None and self._gnmi_is_available():
            try:
                result = fn(self._gnmi)
                logger.debug(
                    "SonicTelemetryAdapter: served via gNMI (transport=%s)",
                    result.transport_used if hasattr(result, "transport_used") else "N/A",
                )
                return result
            except Exception as exc:
                logger.warning(
                    "gNMI call failed (%s); falling back to CLI. Error: %s",
                    type(exc).__name__, exc,
                )
        result = fn(self._cli)
        logger.debug("SonicTelemetryAdapter: served via CLI (fallback)")
        return result

    def _gnmi_is_available(self) -> bool:
        """Probe gNMI availability once and cache the result."""
        if self._gnmi_available is None:
            self._gnmi_available = self._gnmi.is_available()
            if self._gnmi_available:
                logger.info("SonicTelemetryAdapter: gNMI is available on %s", self._dut.hostname)
            else:
                logger.info(
                    "SonicTelemetryAdapter: gNMI not available on %s — using CLI",
                    self._dut.hostname,
                )
        return self._gnmi_available
