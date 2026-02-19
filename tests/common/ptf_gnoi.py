"""
PTF-based gNOI client wrapper providing high-level gNOI operations.

This module provides a user-friendly wrapper around PtfGrpc for gNOI
(gRPC Network Operations Interface) operations, hiding the low-level
gRPC complexity behind clean, Pythonic method interfaces.
"""
import logging
from typing import Dict

logger = logging.getLogger(__name__)


class PtfGnoi:
    """
    High-level gNOI client wrapper.

    This class provides clean, Pythonic interfaces for gNOI operations,
    wrapping the low-level PtfGrpc client and handling gNOI-specific
    data transformations and validations.
    """

    def __init__(self, grpc_client):
        """
        Initialize PtfGnoi wrapper.

        Args:
            grpc_client: PtfGrpc instance for low-level gRPC operations
        """
        self.grpc_client = grpc_client
        logger.info("Initialized PtfGnoi wrapper with %s", grpc_client)

    def system_time(self) -> Dict:
        """Get the current system time from the device."""
        logger.debug("Getting system time via gNOI System.Time")
        response = self.grpc_client.call_unary("gnoi.system.System", "Time")

        if "time" in response:
            try:
                response["time"] = int(response["time"])
                logger.debug("System time: %s ns", response["time"])
            except (ValueError, TypeError) as exc:
                logger.warning("Failed to convert time to int: %s", exc)

        return response

    def file_stat(self, remote_file: str) -> Dict:
        """Get file statistics from the device."""
        logger.debug("Getting file stats from device: %s", remote_file)
        request = {"path": remote_file}

        try:
            response = self.grpc_client.call_unary("gnoi.file.File", "Stat", request)

            if "stats" in response and isinstance(response["stats"], list):
                for stat in response["stats"]:
                    for field in ["last_modified", "permissions", "size", "umask"]:
                        if field in stat:
                            try:
                                stat[field] = int(stat[field])
                            except (ValueError, TypeError) as exc:
                                logger.warning(
                                    "Failed to convert %s to int: %s", field, exc
                                )

            logger.info("Successfully got file stats: %s", remote_file)
            return response

        except Exception as exc:
            low = str(exc).lower()
            if "not found" in low or "no such file" in low:
                raise FileNotFoundError(f"File not found: {remote_file}") from exc
            raise

    def kill_process(self, name: str, restart: bool = False, signal="SIGNAL_TERM") -> Dict:
        """
        Kill (and optionally restart) a process/service via gNOI System.KillProcess.

        NOTE:
        grpcurl JSON->proto mapping is most reliable when enums are passed as
        their string names (e.g., "SIGNAL_TERM"), not numeric values.
        """
        # Normalize TERM representations to the enum name expected by grpcurl mapping.
        if isinstance(signal, int):
            # Keep non-1 ints as-is for negative tests, but map 1 => SIGNAL_TERM
            signal = "SIGNAL_TERM" if signal == 1 else signal
        elif isinstance(signal, str):
            low = signal.strip().lower()
            if low in ("sigterm", "term", "signal_term", "1"):
                signal = "SIGNAL_TERM"

        logger.debug(
            "Calling gNOI System.KillProcess: name=%s restart=%s signal=%s",
            name,
            restart,
            signal,
        )
        request = {"name": name, "restart": restart, "signal": signal}
        return self.grpc_client.call_unary("gnoi.system.System", "KillProcess", request)

    def upgrade_status(self, upgrade_id: str) -> Dict:
        """Get the status of an upgrade operation from the device."""
        logger.debug("Getting upgrade status for Upgrade ID: %s", upgrade_id)
        request = {"id": upgrade_id}

        response = self.grpc_client.call_unary("gnoi.upgrade.Upgrade", "Status", request)

        if "status" not in response:
            raise ValueError("Missing 'status' in upgrade status response")

        logger.debug("Received upgrade status response: %s", response)
        return response

    def __str__(self):
        return f"PtfGnoi(grpc_client={self.grpc_client})"

    def __repr__(self):
        return self.__str__()
