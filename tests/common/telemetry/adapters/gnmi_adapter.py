"""
gNMI transport adapter for SONiC interface counters.

This adapter queries SONiC's gNMI server using the sonic-db origin path
(COUNTERS_DB) which is reliably supported across all SONiC builds.  It does
NOT use OpenConfig paths because those are not consistently supported.

YANG path pattern used
----------------------
Port OID lookup::

    /sonic-db:COUNTERS_DB/localhost/COUNTERS_PORT_NAME_MAP/<iface>

Counter hash::

    /sonic-db:COUNTERS_DB/localhost/COUNTERS/<oid>

Queue OID lookup::

    /sonic-db:COUNTERS_DB/localhost/COUNTERS_QUEUE_NAME_MAP/<iface>:<q>

Queue counter hash::

    /sonic-db:COUNTERS_DB/localhost/COUNTERS/<oid>


gNMI is accessed via py_gnmicli running on ptfhost (same approach used by
the existing tests/gnmi/helper.py).
"""

import json
import logging
import re
from typing import Dict, Optional

from tests.common.helpers.gnmi_utils import GNMIEnvironment
from .base_adapter import BaseAdapter, AdapterTransport, InterfaceCounters, QueueCounters

logger = logging.getLogger(__name__)

# SAI counter names that compose RX_OK / TX_OK
_RX_OK_STATS = [
    "SAI_PORT_STAT_IF_IN_UCAST_PKTS",
    "SAI_PORT_STAT_IF_IN_MULTICAST_PKTS",
    "SAI_PORT_STAT_IF_IN_BROADCAST_PKTS",
]
_TX_OK_STATS = [
    "SAI_PORT_STAT_IF_OUT_UCAST_PKTS",
    "SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS",
    "SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS",
]
_RX_ERR_STAT = "SAI_PORT_STAT_IF_IN_ERRORS"
_TX_ERR_STAT = "SAI_PORT_STAT_IF_OUT_ERRORS"
_RX_DRP_STAT = "SAI_PORT_STAT_IF_IN_DISCARDS"
_TX_DRP_STAT = "SAI_PORT_STAT_IF_OUT_DISCARDS"
_RX_BPS_STAT = "SAI_PORT_STAT_IF_IN_OCTETS"
_TX_BPS_STAT = "SAI_PORT_STAT_IF_OUT_OCTETS"

# Queue counter fields returned per queue OID
_QUEUE_STAT_KEYS = [
    "SAI_QUEUE_STAT_PACKETS",
    "SAI_QUEUE_STAT_BYTES",
    "SAI_QUEUE_STAT_DROPPED_PACKETS",
    "SAI_QUEUE_STAT_DROPPED_BYTES",
]

# Canonical portstat-compatible names for queue counters: UC<n>_PKTS etc.
_QUEUE_STAT_PORTSTAT_MAP = {
    "SAI_QUEUE_STAT_PACKETS": "PKTS",
    "SAI_QUEUE_STAT_BYTES": "BYTES",
    "SAI_QUEUE_STAT_DROPPED_PACKETS": "DROP_PKTS",
    "SAI_QUEUE_STAT_DROPPED_BYTES": "DROP_BYTES",
}


class GNMIAdapter(BaseAdapter):
    """
    Fetch SONiC interface counters via the gNMI server.

    Args:
        duthost: ansible module handle for the DUT.
        ptfhost: ansible module handle for the PTF container where
                 py_gnmicli is available under
                 ``/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py``.
    """

    def __init__(self, duthost, ptfhost):
        self._dut = duthost
        self._ptf = ptfhost
        self._env: Optional[GNMIEnvironment] = None

    # Availability probe

    def is_available(self) -> bool:
        """Return True if the gNMI server is listening on the DUT."""
        try:
            env = self._get_env()
            cmd = "ss -ltnp 'sport = :{port}'".format(port=env.gnmi_port)
            result = self._dut.shell(cmd, module_ignore_errors=True)
            return result["rc"] == 0 and result["stdout"].strip() != ""
        except Exception as exc:
            logger.warning("gNMI availability probe failed: %s", exc)
            return False

    # Public API

    def get_interface_counters(self, interface: str) -> InterfaceCounters:
        """Return a single-interface counter snapshot via gNMI."""
        oid = self._get_port_oid(interface)
        raw = self._gnmi_get_hash(
            "/sonic-db:COUNTERS_DB/localhost/COUNTERS/{}".format(oid)
        )
        return self._parse_port_counters(raw)

    def get_all_interface_counters(self) -> Dict[str, InterfaceCounters]:
        """Return counters for every interface listed in COUNTERS_PORT_NAME_MAP."""
        name_map = self._gnmi_get_hash(
            "/sonic-db:COUNTERS_DB/localhost/COUNTERS_PORT_NAME_MAP"
        )
        result: Dict[str, InterfaceCounters] = {}
        for iface, oid in name_map.items():
            try:
                raw = self._gnmi_get_hash(
                    "/sonic-db:COUNTERS_DB/localhost/COUNTERS/{}".format(oid)
                )
                result[iface] = self._parse_port_counters(raw)
            except Exception as exc:
                logger.warning("Skipping %s: %s", iface, exc)
        return result

    def get_queue_stats(self, interface: str) -> QueueCounters:
        """Return per-queue counters for *interface*."""
        # Discover all queues for this interface from COUNTERS_QUEUE_NAME_MAP
        queue_map = self._gnmi_get_hash(
            "/sonic-db:COUNTERS_DB/localhost/COUNTERS_QUEUE_NAME_MAP"
        )
        # Keys are "<iface>:<queue_index>" — filter to this interface only
        prefix = interface + ":"
        stats: Dict[str, int] = {}
        for key, oid in queue_map.items():
            if not key.startswith(prefix):
                continue
            q_index = key[len(prefix):]
            try:
                raw = self._gnmi_get_hash(
                    "/sonic-db:COUNTERS_DB/localhost/COUNTERS/{}".format(oid)
                )
                for sai_key, portstat_suffix in _QUEUE_STAT_PORTSTAT_MAP.items():
                    canonical = "UC{}_{}".format(q_index, portstat_suffix)
                    stats[canonical] = int(raw.get(sai_key, 0))
            except Exception as exc:
                logger.warning("Queue %s:%s: %s", interface, q_index, exc)
        return QueueCounters(stats=stats, transport_used=AdapterTransport.GNMI)

    def clear_interface_counters(self) -> None:
        """gNMI does not support clearing counters; no-op with a warning."""
        logger.warning(
            "GNMIAdapter.clear_interface_counters(): gNMI has no counter-clear "
            "RPC — use CLIAdapter or SonicTelemetryAdapter(transport=AUTO) instead."
        )

    # Internal helpers

    def _get_env(self) -> GNMIEnvironment:
        if self._env is None:
            self._env = GNMIEnvironment(self._dut, GNMIEnvironment.GNMI_MODE)
        return self._env

    def _build_py_gnmicli_cmd(self, path: str) -> str:
        """Build the py_gnmicli GET command string for *path*."""
        env = self._get_env()
        ip = self._dut.mgmt_ip
        port = env.gnmi_port
        # Strip the 'sonic-db:' origin prefix from the path for the --xpath arg
        xpath = path.replace("sonic-db:", "")
        cmd = "/root/env-python3/bin/python /root/gnxi/gnmi_cli_py/py_gnmicli.py "
        cmd += "--timeout 30 "
        cmd += "-t {ip} -p {port} ".format(ip=ip, port=port)
        cmd += "-xo sonic-db "
        cmd += "-rcert /root/gnmiCA.pem "
        cmd += "-pkey /root/gnmiclient.key "
        cmd += "-cchain /root/gnmiclient.crt "
        cmd += "--encoding 4 "
        cmd += "-m get "
        cmd += "--xpath {}".format(xpath)
        return cmd

    def _gnmi_get_raw(self, path: str) -> str:
        """Execute a gNMI GET for *path* and return the raw string payload."""
        cmd = self._build_py_gnmicli_cmd(path)
        output = self._ptf.shell(cmd, module_ignore_errors=True)
        msg = output["stdout"].replace("\\", "")
        if "GRPC error" in msg:
            raise RuntimeError("gNMI GET failed for path {!r}: {}".format(path, msg))
        mark = "The GetResponse is below\n" + "-" * 25 + "\n"
        if mark not in msg:
            raise RuntimeError(
                "Unexpected gNMI response for path {!r}: {}".format(path, msg)
            )
        payload = msg.split(mark, 1)[1].split("-" * 25)[0].strip()
        return payload

    def _gnmi_get_hash(self, path: str) -> Dict[str, str]:
        """
        Execute a gNMI GET and parse the result as a flat key:value dict.

        The py_gnmicli output for a hash table looks like::

            {
              "SAI_PORT_STAT_IF_IN_UCAST_PKTS": "12345",
              ...
            }

        or, for COUNTERS_PORT_NAME_MAP, like::

            {
              "Ethernet0": "oid:0x100000000001c",
              ...
            }
        """
        raw = self._gnmi_get_raw(path)
        # py_gnmicli may emit the JSON object directly or wrap it in extra text
        # Try to locate the first '{' and parse from there
        brace = raw.find("{")
        if brace == -1:
            # Might be a single leaf value
            raw = raw.strip().strip('"')
            return {"value": raw}
        try:
            return json.loads(raw[brace:])
        except json.JSONDecodeError:
            # Fall back: parse "key": "value" pairs manually
            pairs = re.findall(r'"([^"]+)"\s*:\s*"([^"]*)"', raw)
            return dict(pairs)

    def _get_port_oid(self, interface: str) -> str:
        """Return the COUNTERS_DB OID for *interface*."""
        path = "/sonic-db:COUNTERS_DB/localhost/COUNTERS_PORT_NAME_MAP/{}".format(
            interface
        )
        raw = self._gnmi_get_raw(path)
        oid = raw.strip().strip('"')
        if not oid.startswith("oid:"):
            raise RuntimeError(
                "Unexpected OID format for {!r}: {!r}".format(interface, oid)
            )
        return oid

    @staticmethod
    def _sai_to_portstat(raw: Dict[str, str]) -> InterfaceCounters:
        """
        Convert a raw SAI counter hash to an InterfaceCounters dataclass.

        RX_OK / TX_OK are the *sum* of ucast + mcast + bcast SAI stats.
        """

        def _int(key: str) -> int:
            return int(raw.get(key, 0))

        rx_ok = sum(_int(k) for k in _RX_OK_STATS)
        tx_ok = sum(_int(k) for k in _TX_OK_STATS)

        return InterfaceCounters(
            RX_OK=rx_ok,
            TX_OK=tx_ok,
            RX_ERR=_int(_RX_ERR_STAT),
            TX_ERR=_int(_TX_ERR_STAT),
            RX_DRP=_int(_RX_DRP_STAT),
            TX_DRP=_int(_TX_DRP_STAT),
            RX_BPS=float(_int(_RX_BPS_STAT)),  # bytes, not rate
            TX_BPS=float(_int(_TX_BPS_STAT)),  # bytes, not rate
            RX_UTIL=0.0,   # not available via gNMI
            TX_UTIL=0.0,   # not available via gNMI
            RX_OVR=0,      # not in COUNTERS_DB
            TX_OVR=0,      # not in COUNTERS_DB
            transport_used=AdapterTransport.GNMI,
        )

    def _parse_port_counters(self, raw: Dict[str, str]) -> InterfaceCounters:
        return self._sai_to_portstat(raw)
