"""
PTF-based gNOI client wrapper providing high-level gNOI operations.

This module provides a user-friendly wrapper around PtfGrpc for gNOI
(gRPC Network Operations Interface) operations, hiding the low-level
gRPC complexity behind clean, Pythonic method interfaces.
"""
import logging
from typing import Dict

logger = logging.getLogger(__name__)


# Signal types as defined in gNOI system.proto
# https://github.com/openconfig/gnoi/blob/main/system/system.proto#L352
SIGNAL_TERM = "SIGNAL_TERM"  # Terminate the process gracefully
SIGNAL_KILL = "SIGNAL_KILL"  # Terminate the process immediately
SIGNAL_HUP = "SIGNAL_HUP"    # Reload the process configuration
SIGNAL_ABRT = "SIGNAL_ABRT"  # Terminate immediately and dump core


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
        logger.info(f"Initialized PtfGnoi wrapper with {grpc_client}")

    def system_time(self) -> Dict:
        """
        Get the current system time from the device.

        Returns:
            Dictionary containing:
            - time: Nanoseconds since Unix epoch (int)

        Raises:
            GrpcConnectionError: If connection fails
            GrpcCallError: If the gRPC call fails
            GrpcTimeoutError: If the call times out
        """
        logger.debug("Getting system time via gNOI System.Time")

        # Make the low-level gRPC call
        response = self.grpc_client.call_unary("gnoi.system.System", "Time")

        # Convert time string to int for consistency
        if "time" in response:
            try:
                response["time"] = int(response["time"])
                logger.debug(f"System time: {response['time']} ns")
            except (ValueError, TypeError) as e:
                logger.warning(f"Failed to convert time to int: {e}")

        return response

    # File service operations
    # TODO: Add file_get(), file_put(), file_remove() methods
    # These are left for future implementation when gNOI File service is stable

    def file_stat(self, remote_file: str) -> Dict:
        """
        Get file statistics from the device.

        Args:
            remote_file: Path to the file on the device

        Returns:
            File statistics including size, permissions, timestamps

        Raises:
            GrpcConnectionError: If connection fails
            GrpcCallError: If the gRPC call fails
            GrpcTimeoutError: If the call times out
            FileNotFoundError: If the file doesn't exist
        """
        logger.debug(f"Getting file stats from device: {remote_file}")

        request = {"path": remote_file}

        try:
            response = self.grpc_client.call_unary("gnoi.file.File", "Stat", request)

            # Convert numeric strings to proper types for consistency
            if "stats" in response and isinstance(response["stats"], list):
                for stat in response["stats"]:
                    # Convert numeric fields from strings to integers
                    for field in ["last_modified", "permissions", "size", "umask"]:
                        if field in stat:
                            try:
                                stat[field] = int(stat[field])
                            except (ValueError, TypeError) as e:
                                logger.warning(f"Failed to convert {field} to int: {e}")

            logger.info(f"Successfully got file stats: {remote_file}")
            return response

        except Exception as e:
            if "not found" in str(e).lower() or "no such file" in str(e).lower():
                raise FileNotFoundError(f"File not found: {remote_file}") from e
            raise

    def kill_process(self, name: str, restart: bool = False, signal=SIGNAL_TERM) -> Dict:
            """
            Kill (and optionally restart) a process/service via gNOI System.KillProcess.

            Signal types (as defined in gNOI system.proto):
                - SIGNAL_TERM: Terminate the process gracefully (default)
                - SIGNAL_KILL: Terminate the process immediately
                - SIGNAL_HUP: Reload the process configuration
                - SIGNAL_ABRT: Terminate immediately and dump a core file

            NOTE:
                Current SONiC implementation only supports SIGNAL_TERM. Other signal
                types will be rejected with an error. Use the module-level constants
                (SIGNAL_TERM, SIGNAL_KILL, SIGNAL_HUP, SIGNAL_ABRT) for signal values.

            Technical note:
                grpcurl JSON->proto mapping is most reliable when enums are passed as
                their string names (e.g., "SIGNAL_TERM"), not numeric values.

            Args:
                name: Process/service name to kill
                restart: Whether to restart the process after killing
                signal: Signal type (use SIGNAL_* constants from this module)

            Returns:
                Dictionary response from gNOI server (typically empty on success)

            Raises:
                GrpcConnectionError: If connection fails
                GrpcCallError: If the gRPC call fails (e.g., unsupported signal)
                GrpcTimeoutError: If the call times out

            Example:
                >>> from tests.common.ptf_gnoi import PtfGnoi, SIGNAL_TERM
                >>> ptf_gnoi = PtfGnoi(grpc_client)
                >>> ptf_gnoi.kill_process("snmp", restart=True, signal=SIGNAL_TERM)
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

    def __str__(self):
        return f"PtfGnoi(grpc_client={self.grpc_client})"

    def __repr__(self):
        return self.__str__()
