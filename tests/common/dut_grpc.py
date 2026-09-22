"""
DUT-local gRPC client using grpcurl over Unix domain socket.

This module provides a grpcurl-based gRPC client that runs on the DUT host
via duthost.shell(), connecting over a Unix domain socket for local testing
without TLS overhead.

Unlike PtfGrpc (which runs on the PTF container over TCP), DutGrpc always
uses plaintext UDS and has no TLS certificate configuration.
"""
import json
import shlex
import logging

logger = logging.getLogger(__name__)


class DutGrpcError(Exception):
    """Base exception for DutGrpc operations."""
    pass


class DutGrpcConnectionError(DutGrpcError):
    """Connection-related gRPC errors (socket not found, connection refused)."""
    pass


class DutGrpcCallError(DutGrpcError):
    """gRPC method call errors (unknown service, invalid response)."""
    pass


class DutGrpcTimeoutError(DutGrpcError):
    """gRPC timeout errors."""
    pass


class DutGrpc:
    """
    DUT-local gRPC client using grpcurl over Unix domain socket.

    Executes grpcurl commands on the DUT host via duthost.shell() to interact
    with gRPC services over a local UDS. Always uses plaintext (no TLS).

    Usage:
        client = DutGrpc(duthost)
        services = client.list_services()
        result = client.call_unary("gnoi.system.System", "Time")
    """

    def __init__(self, duthost, socket_path="/var/run/gnmi/gnmi.sock"):
        """
        Args:
            duthost: DUT host instance (must support .shell())
            socket_path: Path to the gNMI Unix domain socket
        """
        self.duthost = duthost
        self.socket_path = socket_path
        self.target = f"unix:///{socket_path}"
        self.timeout = 10

    def configure_timeout(self, timeout_seconds):
        """Configure connection timeout in seconds."""
        self.timeout = int(timeout_seconds)

    def _build_cmd(self, extra_args=None, service_method=None, metadata=None):
        """
        Build a grpcurl shell command string.

        Args:
            extra_args: Additional command arguments.
            service_method: gRPC service/method target.
            metadata: Optional gRPC metadata as dict or list of (key, value) tuples.

        Returns a string suitable for duthost.shell().
        """
        parts = [
            "grpcurl", "-plaintext", "-format", "json",
            "-connect-timeout", str(self.timeout),
        ]
        if metadata:
            items = metadata.items() if isinstance(metadata, dict) else metadata
            for name, value in items:
                parts.extend(["-H", shlex.quote(f"{name}: {value}")])
        if extra_args:
            parts.extend(extra_args)
        parts.append(shlex.quote(self.target))
        if service_method:
            parts.append(shlex.quote(service_method))
        return " ".join(parts)

    def _execute(self, cmd):
        """Execute a grpcurl command and return the result dict, or raise on error."""
        logger.debug("DutGrpc executing: %s", cmd)
        result = self.duthost.shell(cmd, module_ignore_errors=True)

        if result["rc"] != 0:
            stderr = (result.get("stderr") or "").strip()
            stdout = (result.get("stdout") or "").strip()
            err_text = stderr or stdout

            if any(kw in err_text.lower() for kw in (
                "connection refused", "no such file", "dial",
                "connect:", "connection failed",
            )):
                raise DutGrpcConnectionError(f"Connection failed to {self.target}: {err_text}")

            if any(kw in err_text.lower() for kw in (
                "timeout", "deadline exceeded",
            )):
                raise DutGrpcTimeoutError(f"Timed out after {self.timeout}s: {err_text}")

            if any(kw in err_text.lower() for kw in (
                "unknown service", "unknown method", "not found", "unimplemented",
            )):
                raise DutGrpcCallError(f"Service/method error: {err_text}")

            raise DutGrpcError(f"grpcurl failed (rc={result['rc']}): {err_text}")

        return result

    def list_services(self):
        """
        List available gRPC services via reflection.

        Returns:
            List of service name strings (grpc.reflection.* filtered out).
        """
        cmd = self._build_cmd(service_method="list")
        result = self._execute(cmd)

        services = []
        for line in result["stdout"].strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("grpc."):
                services.append(line)
        return services

    def describe(self, symbol):
        """
        Describe a gRPC service or method via reflection.

        Args:
            symbol: Fully qualified service or method name.

        Returns:
            Dict with 'symbol' and 'description' keys.
        """
        cmd = self._build_cmd(service_method=f"describe {symbol}")
        result = self._execute(cmd)
        return {"symbol": symbol, "description": result["stdout"].strip()}

    def call_unary(self, service, method, request=None, metadata=None):
        """
        Make a unary gRPC call.

        Args:
            service: Service name (e.g. "gnoi.system.System")
            method: Method name (e.g. "Time")
            request: Optional request dict.
            metadata: Optional gRPC metadata as dict or list of (key, value) tuples.

        Returns:
            Parsed JSON response dict.
        """
        service_method = f"{service}/{method}"
        request_json = json.dumps(request) if request else "{}"
        extra_args = ["-d", shlex.quote(request_json)]
        cmd = self._build_cmd(extra_args=extra_args, service_method=service_method, metadata=metadata)
        result = self._execute(cmd)

        try:
            return json.loads(result["stdout"].strip())
        except json.JSONDecodeError as e:
            raise DutGrpcCallError(f"Invalid JSON from {service_method}: {e}")

    def call_server_streaming(self, service, method, request=None, metadata=None):
        """
        Make a server-streaming gRPC call.

        Args:
            service: Service name
            method: Method name
            request: Optional request dict.
            metadata: Optional gRPC metadata as dict or list of (key, value) tuples.

        Returns:
            List of parsed JSON response dicts.
        """
        service_method = f"{service}/{method}"
        request_json = json.dumps(request) if request else "{}"
        extra_args = ["-d", shlex.quote(request_json)]
        cmd = self._build_cmd(extra_args=extra_args, service_method=service_method, metadata=metadata)
        result = self._execute(cmd)

        responses = []
        stdout = result["stdout"].strip()

        # Try as single JSON first (grpcurl may wrap in one object)
        try:
            responses.append(json.loads(stdout))
            return responses
        except json.JSONDecodeError:
            pass

        # Fall back to line-by-line for streaming output
        for line in stdout.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                responses.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        if not responses:
            raise DutGrpcCallError(f"No valid responses from streaming call {service_method}")

        return responses

    def __str__(self):
        return f"DutGrpc(target={self.target})"

    def __repr__(self):
        return self.__str__()
