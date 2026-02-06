"""
PTF-based gNOI client wrapper providing high-level gNOI operations.

This module provides a user-friendly wrapper around PtfGrpc for gNOI
(gRPC Network Operations Interface) operations, hiding the low-level
gRPC complexity behind clean, Pythonic method interfaces.
"""
import logging
from typing import Dict, Optional

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

    def __str__(self):
        return f"PtfGnoi(grpc_client={self.grpc_client})"

    def __repr__(self):
        return self.__str__()

    def system_reboot(
        self,
        method: str,
        delay: Optional[int] = None,
        message: Optional[str] = None,
        force: bool = False,
    ) -> Dict:
        """
        Reboot the DUT using gNOI System.Reboot.

        Note:
            Blocking behavior is server/implementation dependent and is NOT
            controlled by this client wrapper.
            In most SONiC/embedded implementations, System.Reboot behaves like a
            "trigger" RPC:
            - The server may start rebooting immediately after receiving the request.
            - The gRPC/TLS channel can be torn down mid-RPC as the control plane goes down.
            - As a result, the client may observe UNAVAILABLE/EOF/connection reset even
                if the reboot was successfully initiated.

            Even when the RPC returns successfully, it typically only confirms the reboot
            request was accepted, not that the device has completed reboot and is ready.

        Args:
            method: RebootMethod enum name (e.g., "WARM", "COLD")
            delay: Optional delay (seconds) before reboot, if supported by server
            message: Optional reboot message/reason string
            force: Optional force flag (if supported by server)

        Returns:
            Dictionary response from gNOI server.

        Raises:
            GrpcConnectionError / GrpcCallError / GrpcTimeoutError:
                As raised by underlying grpc_client.call_unary.
            ValueError: If inputs are invalid.
        """
        if not method:
            raise ValueError("method must be provided")

        request: Dict = {"method": method}

        # Only include optional fields if specified
        if delay is not None:
            request["delay"] = delay
        if message:
            request["message"] = message
        if force:
            request["force"] = True

        logger.debug("Reboot via gNOI System.Reboot: %s", request)

        response = self.grpc_client.call_unary("gnoi.system.System", "Reboot", request)
        logger.info("Reboot request sent: method=%s delay=%s force=%s", method, delay, force)
        return response