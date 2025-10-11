"""
gRPC Client Abstraction Layer

Provides polymorphic client interface for gRPC services (gNOI, gNMI, gNSI, etc.) with support for:
- CLI-based client using grpcurl (implemented)
- Native Python gRPC client (future implementation)

Supports 4 RPC patterns:
- Unary: Single request → Single response
- Server Streaming: Single request → Stream of responses
- Client Streaming: Stream of requests → Single response
- Bidirectional Streaming: Stream ↔ Stream
"""

import json
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class GrpcClientBase(ABC):
    """Abstract base class for gRPC clients."""

    def __init__(self, target, port=8080, insecure=True):
        """Initialize gRPC client.

        Args:
            target: Target device IP/hostname
            port: gRPC port (default 8080)
            insecure: Skip TLS verification (default True)
        """
        self.target = target
        self.port = port
        self.insecure = insecure
        self._initialized = False

    @abstractmethod
    def connect(self):
        """Initialize client resources.

        For CLI client: Download grpcurl tool
        For native client: Create gRPC channel and stubs

        Should be idempotent - safe to call multiple times.
        """
        pass

    @abstractmethod
    def close(self):
        """Clean up client resources.

        For CLI client: Cleanup temporary files (optional)
        For native client: Close gRPC channel
        """
        pass

    @abstractmethod
    def call_unary(self, service, method, request=None):
        """Call unary RPC (single request → single response).

        Args:
            service: Full service path (e.g., "gnoi.system.System", "gnmi.gNMI")
            method: Method name (e.g., "Time", "Get")
            request: Request data as dict (optional)

        Returns:
            dict: Response data

        Raises:
            RuntimeError: If RPC call fails
        """
        pass

    @abstractmethod
    def call_server_stream(self, service, method, request=None):
        """Call server-streaming RPC (single request → stream of responses).

        Args:
            service: Full service path (e.g., "gnoi.system.System")
            method: Method name
            request: Request data as dict (optional)

        Returns:
            Generator[dict]: Stream of response dicts

        Raises:
            RuntimeError: If RPC call fails
            NotImplementedError: If client doesn't support streaming
        """
        pass

    @abstractmethod
    def call_client_stream(self, service, method, request_stream):
        """Call client-streaming RPC (stream of requests → single response).

        Args:
            service: Full service path (e.g., "gnoi.file.File")
            method: Method name
            request_stream: Iterable/generator of request dicts

        Returns:
            dict: Response data

        Raises:
            RuntimeError: If RPC call fails
            NotImplementedError: If client doesn't support streaming
        """
        pass

    @abstractmethod
    def call_bidi_stream(self, service, method, request_stream):
        """Call bidirectional-streaming RPC (stream ↔ stream).

        Args:
            service: Full service path (e.g., "gnoi.file.File")
            method: Method name
            request_stream: Iterable/generator of request dicts

        Returns:
            Generator[dict]: Stream of response dicts

        Raises:
            RuntimeError: If RPC call fails
            NotImplementedError: If client doesn't support streaming
        """
        pass


class GrpcCliClient(GrpcClientBase):
    """gRPC client using grpcurl CLI tool.

    Supports unary RPCs only. Streaming RPCs raise NotImplementedError.
    """

    GRPCURL_VERSION = "v1.9.1"
    GRPCURL_PATH = "/tmp/grpcurl"

    def __init__(self, vmhost, target, port=8080, insecure=True):
        """Initialize CLI-based gRPC client.

        Args:
            vmhost: Ansible host object where grpcurl will run
            target: Target device IP/hostname
            port: gRPC port (default 8080)
            insecure: Skip TLS verification (default True)
        """
        super().__init__(target, port, insecure)
        self.vmhost = vmhost

    def connect(self):
        """Download and install grpcurl if not already present.

        Idempotent - checks if grpcurl exists before downloading.
        Downloads to /tmp/grpcurl on vmhost.
        """
        if self._initialized:
            logger.info("Client already connected")
            return

        # Check if grpcurl exists
        check_cmd = f"test -f {self.GRPCURL_PATH} && echo 'exists'"
        result = self.vmhost.shell(check_cmd, module_ignore_errors=True)

        if "exists" not in result.get('stdout', ''):
            logger.info(f"Downloading grpcurl {self.GRPCURL_VERSION}")
            # Note: Filename format is grpcurl_1.9.1_linux_x86_64.tar.gz
            version_without_v = self.GRPCURL_VERSION.lstrip('v')
            url = (
                f"https://github.com/fullstorydev/grpcurl/releases/download/"
                f"{self.GRPCURL_VERSION}/grpcurl_{version_without_v}_linux_x86_64.tar.gz"
            )
            download_cmd = f"""
            curl -L {url} -o /tmp/grpcurl.tar.gz && \
            tar -xzf /tmp/grpcurl.tar.gz -C /tmp grpcurl && \
            chmod +x {self.GRPCURL_PATH} && \
            rm -f /tmp/grpcurl.tar.gz
            """
            self.vmhost.shell(download_cmd)
            logger.info("grpcurl installed successfully")
        else:
            logger.info("grpcurl already installed")

        self._initialized = True

    def close(self):
        """Cleanup client resources.

        Note: grpcurl is kept on vmhost for reuse across tests.
        """
        logger.info("GrpcCliClient closed")
        self._initialized = False

    def _build_grpcurl_cmd(self, service, method, data=None):
        """Build grpcurl command with appropriate flags.

        Args:
            service: Full service path (e.g., "gnoi.system.System", "gnmi.gNMI")
            method: Method name (e.g., "Time", "Get")
            data: Optional request data as dict

        Returns:
            str: Complete grpcurl command
        """
        insecure_flag = "-plaintext" if self.insecure else ""
        data_flag = f"-d '{json.dumps(data)}'" if data else "-d '{}'"

        return (
            f"{self.GRPCURL_PATH} {insecure_flag} {data_flag} "
            f"{self.target}:{self.port} {service}/{method}"
        )

    def call_unary(self, service, method, request=None):
        """Call unary RPC via grpcurl.

        Args:
            service: Full service path (e.g., "gnoi.system.System", "gnmi.gNMI")
            method: Method name (e.g., "Time", "Get")
            request: Request data as dict (optional)

        Returns:
            dict: Response data parsed from JSON

        Raises:
            RuntimeError: If client not connected or RPC fails
        """
        if not self._initialized:
            raise RuntimeError("Client not connected. Call connect() first.")

        cmd = self._build_grpcurl_cmd(service, method, request)
        logger.info(f"Calling {service}.{method}")
        logger.debug(f"Command: {cmd}")

        result = self.vmhost.shell(cmd, module_ignore_errors=True)

        if result['rc'] != 0:
            error_msg = result.get('stderr', 'Unknown error')
            raise RuntimeError(f"{service}.{method} RPC failed: {error_msg}")

        response = json.loads(result['stdout'])
        logger.debug(f"{service}.{method} response: {response}")
        return response

    def call_server_stream(self, service, method, request=None):
        """Server streaming not well supported with grpcurl.

        Raises:
            NotImplementedError: Always - use native client for streaming
        """
        raise NotImplementedError(
            "Server streaming not well supported with grpcurl. "
            "Use GrpcNativeClient for streaming RPCs."
        )

    def call_client_stream(self, service, method, request_stream):
        """Client streaming not supported with grpcurl.

        Raises:
            NotImplementedError: Always - use native client for streaming
        """
        raise NotImplementedError(
            "Client streaming not supported with grpcurl. "
            "Use GrpcNativeClient instead."
        )

    def call_bidi_stream(self, service, method, request_stream):
        """Bidirectional streaming not supported with grpcurl.

        Raises:
            NotImplementedError: Always - use native client for streaming
        """
        raise NotImplementedError(
            "Bidirectional streaming not supported with grpcurl. "
            "Use GrpcNativeClient instead."
        )


class GrpcNativeClient(GrpcClientBase):
    """gRPC client using native Python gRPC.

    Future implementation for full streaming support.
    """

    def __init__(self, target, port=8080, insecure=True):
        super().__init__(target, port, insecure)
        self.channel = None
        self.stubs = {}

    def connect(self):
        """Create gRPC channel and stubs.

        Raises:
            NotImplementedError: Native client not yet implemented
        """
        raise NotImplementedError("Native gRPC client not yet implemented")

    def close(self):
        """Close gRPC channel."""
        if self.channel:
            self.channel.close()
        self._initialized = False

    def call_unary(self, service, method, request=None):
        """Call unary RPC via native gRPC.

        Raises:
            NotImplementedError: Native client not yet implemented
        """
        raise NotImplementedError("Native gRPC client not yet implemented")

    def call_server_stream(self, service, method, request=None):
        """Call server-streaming RPC via native gRPC.

        Raises:
            NotImplementedError: Native client not yet implemented
        """
        raise NotImplementedError("Native gRPC client not yet implemented")

    def call_client_stream(self, service, method, request_stream):
        """Call client-streaming RPC via native gRPC.

        Raises:
            NotImplementedError: Native client not yet implemented
        """
        raise NotImplementedError("Native gRPC client not yet implemented")

    def call_bidi_stream(self, service, method, request_stream):
        """Call bidirectional-streaming RPC via native gRPC.

        Raises:
            NotImplementedError: Native client not yet implemented
        """
        raise NotImplementedError("Native gRPC client not yet implemented")


def create_grpc_client(client_type="cli", **kwargs):
    """Factory function to create appropriate gRPC client.

    Args:
        client_type: "cli" or "native"
        **kwargs: Arguments passed to client constructor

    Returns:
        GrpcClientBase: Appropriate client instance

    Raises:
        ValueError: If client_type is unknown

    Examples:
        # CLI client (requires vmhost)
        client = create_grpc_client(
            client_type="cli",
            vmhost=vmhost,
            target="10.250.0.101",
            port=8080,
            insecure=True
        )

        # Native client (future)
        client = create_grpc_client(
            client_type="native",
            target="10.250.0.101",
            port=8080,
            insecure=True
        )
    """
    if client_type == "cli":
        return GrpcCliClient(**kwargs)
    elif client_type == "native":
        return GrpcNativeClient(**kwargs)
    else:
        raise ValueError(f"Unknown client type: {client_type}")
