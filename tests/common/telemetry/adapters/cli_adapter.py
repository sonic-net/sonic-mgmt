"""
CLI fallback adapter for SONiC interface counters.

This adapter drives the DUT via SSH + standard SONiC CLI commands:

    * ``portstat -j``              -> interface counters (JSON)
    * ``sonic-db-cli COUNTERS_DB HGETALL COUNTERS_PORT_NAME_MAP``
    * ``sonic-db-cli COUNTERS_DB HGETALL COUNTERS_QUEUE_NAME_MAP``
    * ``sonic-db-cli COUNTERS_DB HGETALL COUNTERS:<oid>``
    * ``sonic-clear counters``     -> clear interface counters

Field mapping
-------------
``portstat -j`` returns a dict keyed by interface name.  Each value is a
dict with keys that match InterfaceCounters field names exactly:
    RX_OK, TX_OK, RX_ERR, TX_ERR, RX_DRP, TX_DRP,
    RX_BPS, TX_BPS, RX_UTIL, TX_UTIL, RX_OVR, TX_OVR

The adapter casts all values to the correct Python types (int or float).

Queue counters
--------------
sonic-db-cli HGETALL returns raw SAI keys.  This adapter maps them to the
portstat-compatible names (UC<n>_PKTS, UC<n>_BYTES, UC<n>_DROP_PKTS,
UC<n>_DROP_BYTES) using the same mapping as GNMIAdapter.
"""

import json
import logging
from typing import Dict

from .base_adapter import BaseAdapter, AdapterTransport, InterfaceCounters, QueueCounters

logger = logging.getLogger(__name__)

_QUEUE_STAT_PORTSTAT_MAP = {
    "SAI_QUEUE_STAT_PACKETS": "PKTS",
    "SAI_QUEUE_STAT_BYTES": "BYTES",
    "SAI_QUEUE_STAT_DROPPED_PACKETS": "DROP_PKTS",
    "SAI_QUEUE_STAT_DROPPED_BYTES": "DROP_BYTES",
}

# portstat -j emits these numeric fields as strings that may include N/A or "N/A"
_INT_FIELDS = ("RX_OK", "TX_OK", "RX_ERR", "TX_ERR", "RX_DRP", "TX_DRP",
               "RX_OVR", "TX_OVR")
_FLOAT_FIELDS = ("RX_BPS", "TX_BPS", "RX_UTIL", "TX_UTIL")


def _safe_int(value) -> int:
    """Convert a portstat value to int; return 0 for N/A or empty."""
    if value in (None, "", "N/A"):
        return 0
    try:
        return int(str(value).replace(",", ""))
    except (ValueError, TypeError):
        return 0


def _safe_float(value) -> float:
    """Convert a portstat value to float; return 0.0 for N/A or empty."""
    if value in (None, "", "N/A"):
        return 0.0
    try:
        return float(str(value).replace(",", ""))
    except (ValueError, TypeError):
        return 0.0


class CLIAdapter(BaseAdapter):
    """
    Fetch SONiC interface counters via SSH + CLI.

    This adapter is always available as long as SSH connectivity to the DUT
    works.  It is used as a fallback when gNMI is unavailable and as the
    primary source for clearing counters.

    Args:
        duthost: ansible module handle for the DUT.
    """

    def __init__(self, duthost):
        self._dut = duthost

    # Availability probe

    def is_available(self) -> bool:
        """CLIAdapter is always available (requires only SSH)."""
        return True

    # Public API

    def get_interface_counters(self, interface: str) -> InterfaceCounters:
        """Return counters for a single interface via ``portstat -j``."""
        all_counters = self._portstat_json()
        if interface not in all_counters:
            raise RuntimeError(
                "Interface {!r} not found in portstat output. "
                "Available interfaces: {}".format(interface, list(all_counters.keys()))
            )
        return self._row_to_counters(all_counters[interface])

    def get_all_interface_counters(self) -> Dict[str, InterfaceCounters]:
        """Return counters for every interface via ``portstat -j``."""
        all_counters = self._portstat_json()
        return {iface: self._row_to_counters(row) for iface, row in all_counters.items()}

    def get_queue_stats(self, interface: str) -> QueueCounters:
        """Return per-queue counters for *interface* via sonic-db-cli."""
        # Get all queue OIDs for this interface
        queue_name_map = self._db_hgetall("COUNTERS_QUEUE_NAME_MAP")
        prefix = interface + ":"
        stats: Dict[str, int] = {}
        for key, oid in queue_name_map.items():
            if not key.startswith(prefix):
                continue
            q_index = key[len(prefix):]
            try:
                raw = self._db_hgetall("COUNTERS:{}".format(oid))
                for sai_key, portstat_suffix in _QUEUE_STAT_PORTSTAT_MAP.items():
                    canonical = "UC{}_{}".format(q_index, portstat_suffix)
                    stats[canonical] = int(raw.get(sai_key, 0))
            except Exception as exc:
                logger.warning("Queue %s:%s: %s", interface, q_index, exc)
        return QueueCounters(stats=stats, transport_used=AdapterTransport.CLI)

    def clear_interface_counters(self) -> None:
        """Reset interface counters on the DUT via ``sonic-clear counters``."""
        self._dut.shell("sonic-clear counters", module_ignore_errors=True)
        logger.debug("CLIAdapter: interface counters cleared")

    # Internal helpers

    def _portstat_json(self) -> dict:
        """
        Run ``portstat -j`` and return the parsed JSON dict.

        portstat -j prints a header line before the JSON on some builds.
        We locate the first ``{`` to skip any leading text.
        """
        result = self._dut.shell("portstat -j", module_ignore_errors=True)
        stdout = result["stdout"]
        brace = stdout.find("{")
        if brace == -1:
            raise RuntimeError(
                "portstat -j returned no JSON object. Output:\n{}".format(stdout)
            )
        try:
            return json.loads(stdout[brace:])
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Failed to parse portstat -j output: {}\nRaw: {}".format(exc, stdout)
            ) from exc

    def _db_hgetall(self, key: str) -> Dict[str, str]:
        """
        Run ``sonic-db-cli COUNTERS_DB HGETALL <key>`` and return a dict.

        The output format is alternating lines: field, value, field, value …
        """
        cmd = "sonic-db-cli COUNTERS_DB HGETALL {}".format(key)
        result = self._dut.shell(cmd, module_ignore_errors=True)
        stdout = result["stdout"].strip()
        if not stdout:
            return {}
        # Try JSON first (some versions wrap in {})
        if stdout.startswith("{"):
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                pass
        # Fall back: alternating field / value lines
        lines = [line.strip() for line in stdout.splitlines() if line.strip()]
        out: Dict[str, str] = {}
        for i in range(0, len(lines) - 1, 2):
            out[lines[i]] = lines[i + 1]
        return out

    @staticmethod
    def _row_to_counters(row: dict) -> InterfaceCounters:
        """Convert a portstat JSON row to InterfaceCounters."""
        return InterfaceCounters(
            RX_OK=_safe_int(row.get("RX_OK")),
            TX_OK=_safe_int(row.get("TX_OK")),
            RX_ERR=_safe_int(row.get("RX_ERR")),
            TX_ERR=_safe_int(row.get("TX_ERR")),
            RX_DRP=_safe_int(row.get("RX_DRP")),
            TX_DRP=_safe_int(row.get("TX_DRP")),
            RX_BPS=_safe_float(row.get("RX_BPS")),
            TX_BPS=_safe_float(row.get("TX_BPS")),
            RX_UTIL=_safe_float(row.get("RX_UTIL")),
            TX_UTIL=_safe_float(row.get("TX_UTIL")),
            RX_OVR=_safe_int(row.get("RX_OVR")),
            TX_OVR=_safe_int(row.get("TX_OVR")),
            transport_used=AdapterTransport.CLI,
        )
