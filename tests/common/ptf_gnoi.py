"""
PTF-based gNOI client wrapper providing high-level gNOI operations.

This module provides a user-friendly wrapper around PtfGrpc for gNOI
(gRPC Network Operations Interface) operations, hiding the low-level
gRPC complexity behind clean, Pythonic method interfaces.
"""
import logging
from typing import Dict, Optional
from urllib.parse import urlparse

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
            >>> from tests.common.helpers.ptf_gnoi import PtfGnoi, SIGNAL_TERM
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

    def file_transfer_to_remote(
        self,
        url: str,
        local_path: str,
        protocol: Optional[str] = None,
        credentials: Optional[Dict[str, str]] = None,
    ) -> Dict:
        """
        Download a remote artifact to the DUT using gNOI File.TransferToRemote.

        Notes on protocol:
            - For http(s):// URLs, protocol can be inferred from the URL scheme.
            - Some server implementations require an explicit protocol, and some paths may not
            be standard URLs (implementation-specific). Therefore protocol remains an
            optional override:
                * If protocol is None, infer from URL scheme (http/https).
                * If scheme is unknown/empty, protocol must be provided explicitly.

        Args:
            url: Remote URL/path to download from (e.g., http(s)://...)
            local_path: Destination path on DUT (mapped to gNOI request field 'local_path')
            protocol: Optional RemoteDownloadProtocol enum name (e.g., "HTTP", "HTTPS").
                    If None, infer from url scheme.
            credentials: Optional credentials dict {"username": "...", "password": "..."}.
            remote_extra: Optional dict merged into 'remote_download' (implementation-specific).

        Returns:
            Dictionary response from gNOI server.

        Raises:
            GrpcConnectionError / GrpcCallError / GrpcTimeoutError:
                As raised by underlying grpc_client.call_unary.
            ValueError: If inputs are invalid or protocol cannot be inferred.
        """
        if not url:
            raise ValueError("url must be provided")
        if not local_path:
            raise ValueError("local_path must be provided")

        scheme = urlparse(url).scheme.lower()

        # Infer protocol if not explicitly provided
        if protocol is None:
            if scheme == "https":
                protocol = "HTTPS"
            elif scheme == "http":
                protocol = "HTTP"
            else:
                raise ValueError(
                    f"protocol must be provided when url scheme is '{scheme or 'empty'}'"
                )

        protocol = str(protocol).upper()

        # Optional: warn if the override conflicts with URL scheme
        if scheme == "https" and protocol == "HTTP":
            logger.warning("url is https:// but protocol=HTTP; did you mean HTTPS?")
        elif scheme == "http" and protocol == "HTTPS":
            logger.warning("url is http:// but protocol=HTTPS; did you mean HTTP?")

        logger.debug(
            "TransferToRemote via gNOI File.TransferToRemote: url=%s local_path=%s protocol=%s",
            url, local_path, protocol,
        )

        remote_download = {"path": url, "protocol": protocol}

        if credentials:
            remote_download["credentials"] = credentials

        request = {
            "localPath": local_path,
            "remoteDownload": remote_download,
        }

        response = self.grpc_client.call_unary("gnoi.file.File", "TransferToRemote", request)
        logger.info("TransferToRemote completed: %s -> %s", url, local_path)
        return response

    def system_set_package(
        self,
        local_path: str,
        version: Optional[str] = None,
        activate: bool = True,
    ) -> Dict:
        """
        Set the upgrade package on the DUT using gNOI System.SetPackage (client-streaming RPC).

        Sends a single stream message containing package metadata:
        {"package": {<package_field>: <local_path>, "version": ..., "activate": ...}}

        Note: Some server implementations may also require a separate hash message (MD5/SHA).
        This version intentionally omits hash support.

        Args:
            local_path: Path to the package/image on DUT (typically produced by TransferToRemote)
            package_field: Field name used by server inside 'package' ("filename" or "path")
            version: Optional version string
            activate: Whether to activate/switch to the package (commonly required to update "Next")

        Returns:
            Dictionary response from gNOI server.
        """
        if not local_path:
            raise ValueError("local_path must be provided")

        logger.debug(
            "SetPackage via gNOI System.SetPackage (streaming): filename=%s version=%s activate=%s",
            local_path, version, activate,
        )

        pkg: Dict[str, object] = {
            "filename": local_path,
            "activate": bool(activate),
        }
        if version:
            pkg["version"] = version

        response = self.grpc_client.call_client_streaming(
            "gnoi.system.System",
            "SetPackage",
            [{"package": pkg}],
        )

        logger.info("SetPackage completed: %s", local_path)
        return response

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
