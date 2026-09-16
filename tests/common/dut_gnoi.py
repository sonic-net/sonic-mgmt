# tests/common/dut_gnoi.py
"""
DUT-local gNOI client wrapper providing high-level gNOI operations.

This module mirrors PtfGnoi's interface but wraps DutGrpc instead of PtfGrpc,
operating over a local Unix domain socket on the DUT host.
"""
import logging
from typing import Dict

logger = logging.getLogger(__name__)


class DutGnoi:
    """
    DUT-local gNOI client wrapper.

    Provides Pythonic interfaces for gNOI operations, delegating to DutGrpc
    for low-level gRPC transport over UDS.

    Usage:
        grpc = DutGrpc(duthost)
        gnoi = DutGnoi(grpc)
        result = gnoi.system_time()
    """

    def __init__(self, grpc_client):
        """
        Args:
            grpc_client: DutGrpc instance for low-level gRPC operations.
        """
        self.grpc_client = grpc_client

    def system_time(self, metadata=None) -> Dict:
        """
        Get the current system time from the device.

        Args:
            metadata: Optional gRPC metadata (dict or list of (key, value) tuples).

        Returns:
            Dict with 'time' key (nanoseconds since epoch, as int).
        """
        response = self.grpc_client.call_unary("gnoi.system.System", "Time", metadata=metadata)

        if "time" in response:
            try:
                response["time"] = int(response["time"])
            except (ValueError, TypeError) as e:
                logger.warning("Failed to convert time to int: %s", e)

        return response

    def file_stat(self, remote_file: str, metadata=None) -> Dict:
        """
        Get file statistics from the device.

        Args:
            remote_file: Path to the file on the device.
            metadata: Optional gRPC metadata (dict or list of (key, value) tuples).

        Returns:
            Dict with 'stats' key containing file metadata.
        """
        request = {"path": remote_file}
        response = self.grpc_client.call_unary("gnoi.file.File", "Stat", request, metadata=metadata)

        if "stats" in response and isinstance(response["stats"], list):
            for stat in response["stats"]:
                for field in ("last_modified", "permissions", "size", "umask"):
                    if field in stat:
                        try:
                            stat[field] = int(stat[field])
                        except (ValueError, TypeError):
                            pass

        return response

    def kill_process(self, name: str, restart: bool = False, signal: str = "SIGNAL_TERM",
                     metadata=None) -> Dict:
        """
        Kill (and optionally restart) a process via gNOI System.KillProcess.

        Args:
            name: Process/service name to kill.
            restart: Whether to restart after killing.
            signal: Signal type (use SIGNAL_TERM, SIGNAL_KILL, etc.).
            metadata: Optional gRPC metadata (dict or list of (key, value) tuples).

        Returns:
            Dict response (typically empty on success).
        """
        request = {"name": name, "restart": restart, "signal": signal}
        return self.grpc_client.call_unary("gnoi.system.System", "KillProcess", request, metadata=metadata)

    def __str__(self):
        return f"DutGnoi(grpc_client={self.grpc_client})"

    def __repr__(self):
        return self.__str__()
