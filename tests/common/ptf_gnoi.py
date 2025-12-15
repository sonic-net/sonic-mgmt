"""
PTF-based gNOI client wrapper providing high-level gNOI operations.

This module provides a user-friendly wrapper around PtfGrpc for gNOI
(gRPC Network Operations Interface) operations, hiding the low-level
gRPC complexity behind clean, Pythonic method interfaces.
"""
import logging
from typing import Dict
import grpc
from tests.common.ptf_grpc import GrpcCallError

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

        except GrpcCallError as e:
            if e.code() == grpc.StatusCode.NOT_FOUND:
                raise FileNotFoundError(f"File not found: {remote_file}") from e
            raise

    def file_transfer_to_remote(self, local_path: str, remote_url: str, protocol: str = "HTTP",
                                username: str = None, password: str = None) -> Dict:
        """
        Transfer a file from a remote URL to a local path on the device.

        Args:
            local_path: Destination path on the device where file should be saved
            remote_url: Source URL to download the file from
            protocol: Transfer protocol ("HTTP", "HTTPS", "SFTP", "SCP")
            username: Username for authentication (optional)
            password: Password for authentication (optional)

        Returns:
            Dictionary containing:
            - hash: Hash information of the transferred file

        Raises:
            GrpcConnectionError: If connection fails
            GrpcCallError: If the gRPC call fails
            GrpcTimeoutError: If the call times out
            ValueError: If protocol is not supported
        """
        logger.debug(f"Transferring file from {remote_url} to {local_path}")

        # Map protocol strings to enum values
        protocol_map = {
            "UNKNOWN": 0,
            "SFTP": 1,
            "HTTP": 2,
            "HTTPS": 3,
            "SCP": 4
        }

        if protocol.upper() not in protocol_map:
            raise ValueError(f"Unsupported protocol: {protocol}. "
                             f"Supported protocols: {list(protocol_map.keys())}")

        # Build the request
        request = {
            "localPath": local_path,
            "remoteDownload": {
                "path": remote_url,
                "protocol": protocol_map[protocol.upper()]
            }
        }

        # Add credentials if provided
        if username and password:
            request["remoteDownload"]["credentials"] = {
                "username": username,
                "cleartext": password
            }

        try:
            response = self.grpc_client.call_unary("gnoi.file.File", "TransferToRemote", request)

            logger.info(f"Successfully transferred file from {remote_url} to {local_path}")
            return response

        except Exception as e:
            logger.error(f"Failed to transfer file from {remote_url} to {local_path}: {e}")
            raise

    def __str__(self):
        return f"PtfGnoi(grpc_client={self.grpc_client})"

    def __repr__(self):
        return self.__str__()
