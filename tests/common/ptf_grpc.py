"""
PTF-based gRPC client using grpcurl for gNOI/gNMI operations.

This module provides a grpcurl-based gRPC client that runs in the PTF container,
enabling gNOI/gNMI operations against DUT gRPC services with proper process separation.
"""
import json
import logging
import re
from typing import Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class PtfGrpcError(Exception):
    """Base exception for PtfGrpc operations"""
    pass


class GrpcConnectionError(PtfGrpcError):
    """Connection-related gRPC errors"""
    pass


class GrpcCallError(PtfGrpcError):
    """gRPC method call errors"""
    pass


class GrpcTimeoutError(PtfGrpcError):
    """gRPC timeout errors"""
    pass


class PtfGrpc:
    """
    PTF-based gRPC client using grpcurl.
    
    This class executes grpcurl commands in the PTF container to interact with
    gRPC services on the DUT, providing process separation and avoiding the need
    to install gRPC libraries in the test environment.
    """
    
    def __init__(self, ptfhost, target_or_env, plaintext=None, duthost=None):
        """
        Initialize PtfGrpc client.
        
        Args:
            ptfhost: PTF host instance for command execution
            target_or_env: Either target string (host:port) or GNMIEnvironment instance
            plaintext: Force plaintext mode (True/False), auto-detected if None
            duthost: DUT host instance (required for GNMIEnvironment auto-config)
        """
        self.ptfhost = ptfhost
        
        # Configure target and connection parameters
        if hasattr(target_or_env, 'gnmi_port'):
            # Auto-configuration from GNMIEnvironment
            if duthost is None:
                raise ValueError("duthost is required when using GNMIEnvironment auto-configuration")
            self.target = f"{duthost.mgmt_ip}:{target_or_env.gnmi_port}"
            self.plaintext = not target_or_env.use_tls if plaintext is None else plaintext
            self.env = target_or_env
            logger.info(f"Auto-configured PtfGrpc: target={self.target}, plaintext={self.plaintext}")
        else:
            # Manual configuration
            self.target = str(target_or_env)
            self.plaintext = True if plaintext is None else plaintext
            self.env = None
            logger.info(f"Manual PtfGrpc configuration: target={self.target}, plaintext={self.plaintext}")
        
        # Connection configuration
        self.timeout = 10.0  # seconds as float, configurable
        self.max_msg_size = 100 * 1024 * 1024  # 100MB in bytes
        self.headers = {}  # Custom headers
        self.verbose = False  # Enable verbose grpcurl output
    
    def _build_grpcurl_cmd(self, extra_args=None, service_method=None):
        """
        Build grpcurl command with standard options.
        
        Args:
            extra_args: Additional arguments for grpcurl
            service_method: Service.Method for the call (optional)
        
        Returns:
            List of command arguments
        """
        cmd = ["grpcurl"]
        
        # Connection options
        if self.plaintext:
            cmd.append("-plaintext")
        
        # Standard options
        cmd.extend([
            "-connect-timeout", str(self.timeout),
            "-max-msg-sz", str(self.max_msg_size),
            "-format", "json"
        ])
        
        # Add custom headers
        for name, value in self.headers.items():
            cmd.extend(["-H", f"{name}: {value}"])
        
        # Add verbose output if enabled
        if self.verbose:
            cmd.append("-v")
        
        # Add extra arguments
        if extra_args:
            cmd.extend(extra_args)
        
        # Add target
        cmd.append(self.target)
        
        # Add service method if specified
        if service_method:
            cmd.append(service_method)
        
        return cmd
    
    def _execute_grpcurl(self, cmd: List[str], input_data: str = None) -> Dict:
        """
        Execute grpcurl command with enhanced error handling.
        
        Args:
            cmd: grpcurl command as list
            input_data: Optional input data to pipe to command
            
        Returns:
            Dictionary with result information
            
        Raises:
            GrpcConnectionError: Connection-related failures
            GrpcTimeoutError: Timeout-related failures  
            GrpcCallError: Other gRPC call failures
        """
        # Build full command with proper shell escaping
        escaped_cmd = []
        for arg in cmd:
            if ' ' in arg or ':' in arg:
                escaped_cmd.append(f"'{arg}'")
            else:
                escaped_cmd.append(arg)
        
        if input_data:
            full_cmd = f"echo '{input_data}' | {' '.join(escaped_cmd)}"
        else:
            full_cmd = ' '.join(escaped_cmd)
        
        logger.debug(f"Executing: {full_cmd}")
        result = self.ptfhost.shell(full_cmd, module_ignore_errors=True)
        
        # Analyze errors and provide specific exceptions
        if result['rc'] != 0:
            stderr = result['stderr']
            
            # Connection-related errors
            if any(term in stderr.lower() for term in [
                'connection refused', 'no such host', 'network is unreachable',
                'connect: connection refused', 'dial tcp', 'connection failed'
            ]):
                raise GrpcConnectionError(f"Connection failed to {self.target}: {stderr}")
            
            # Timeout-related errors  
            if any(term in stderr.lower() for term in [
                'timeout', 'deadline exceeded', 'context deadline exceeded'
            ]):
                raise GrpcTimeoutError(f"Operation timed out after {self.timeout}s: {stderr}")
            
            # Service/method not found
            if any(term in stderr.lower() for term in [
                'unknown service', 'unknown method', 'not found',
                'unimplemented', 'service not found'
            ]):
                raise GrpcCallError(f"Service or method not found: {stderr}")
            
            # Generic error
            raise PtfGrpcError(f"grpcurl failed: {stderr}")
        
        return result
    
    def configure_timeout(self, timeout_seconds: float) -> None:
        """
        Configure connection timeout.
        
        Args:
            timeout_seconds: Timeout in seconds
        """
        self.timeout = float(timeout_seconds)
        logger.debug(f"Configured timeout: {self.timeout}s")
    
    def add_header(self, name: str, value: str) -> None:
        """
        Add a custom header for gRPC calls.
        
        Args:
            name: Header name
            value: Header value
        """
        self.headers[name] = value
        logger.debug(f"Added header: {name}={value}")
    
    def set_verbose(self, enable: bool = True) -> None:
        """
        Enable/disable verbose grpcurl output.
        
        Args:
            enable: Whether to enable verbose output
        """
        self.verbose = enable
        logger.debug(f"Verbose output: {enable}")
    
    def test_connection(self) -> bool:
        """
        Test if the gRPC connection is working.
        
        Returns:
            True if connection is successful
            
        Raises:
            GrpcConnectionError: If connection fails
            GrpcTimeoutError: If connection times out
        """
        try:
            # Try to list services as a connection test
            services = self.list_services()
            logger.info(f"Connection test passed: found {len(services)} services")
            return True
        except (GrpcConnectionError, GrpcTimeoutError):
            # Re-raise connection/timeout errors as-is
            raise
        except Exception as e:
            # Convert other errors to connection errors
            raise GrpcConnectionError(f"Connection test failed: {e}")
    
    def list_services(self) -> List[str]:
        """
        List all available gRPC services.
        
        Returns:
            List of service names
            
        Raises:
            GrpcConnectionError: If connection fails
            GrpcTimeoutError: If operation times out
        """
        cmd = self._build_grpcurl_cmd(service_method="list")
        result = self._execute_grpcurl(cmd)
        
        # Parse service list from stdout
        services = []
        for line in result['stdout'].strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('grpc.'):
                services.append(line)
        
        logger.info(f"Found {len(services)} services: {services}")
        return services
    
    def describe(self, symbol: str) -> Dict:
        """
        Get description of a service or method.
        
        Args:
            symbol: Service name or Service.Method to describe
            
        Returns:
            Parsed description as dictionary
            
        Raises:
            GrpcConnectionError: If connection fails
            GrpcCallError: If symbol not found
        """
        cmd = self._build_grpcurl_cmd(service_method=f"describe {symbol}")
        result = self._execute_grpcurl(cmd)
        
        # Return raw description for now
        # TODO: Parse protobuf description into structured format
        description = {
            "symbol": symbol,
            "description": result['stdout'].strip()
        }
        
        logger.debug(f"Description for {symbol}: {description}")
        return description
    
    def call_unary(self, service: str, method: str, request: Union[Dict, str] = None) -> Dict:
        """
        Make a unary gRPC call (single request/response).
        
        Args:
            service: Service name (e.g., "gnoi.system.System") 
            method: Method name (e.g., "Time")
            request: Request payload as dict or JSON string (optional for empty request)
        
        Returns:
            Response as dictionary
            
        Raises:
            GrpcConnectionError: If connection fails
            GrpcCallError: If method call fails
            GrpcTimeoutError: If call times out
        """
        service_method = f"{service}/{method}"
        cmd = self._build_grpcurl_cmd(service_method=service_method)
        
        # Prepare request data
        request_data = "{}"  # Default empty JSON
        if request:
            if isinstance(request, dict):
                request_data = json.dumps(request)
            else:
                request_data = str(request)
        
        result = self._execute_grpcurl(cmd, request_data)
        
        try:
            response = json.loads(result['stdout'].strip())
            logger.debug(f"Response from {service_method}: {response}")
            return response
        except json.JSONDecodeError as e:
            raise GrpcCallError(f"Failed to parse response from {service_method}: {e}")
    
    def call_server_streaming(self, service: str, method: str, request: Union[Dict, str] = None) -> List[Dict]:
        """
        Make a server streaming gRPC call (single request, multiple responses).
        
        Args:
            service: Service name 
            method: Method name
            request: Request payload as dict or JSON string
        
        Returns:
            List of response dictionaries
        """
        # TODO: Implement server streaming support
        # For now, treat as unary call
        response = self.call_unary(service, method, request)
        return [response] if response else []
    
    def call_client_streaming(self, service: str, method: str, requests: List[Union[Dict, str]]) -> Dict:
        """
        Make a client streaming gRPC call (multiple requests, single response).
        
        Args:
            service: Service name
            method: Method name  
            requests: List of request payloads
        
        Returns:
            Response dictionary
        """
        # TODO: Implement client streaming support
        # For now, just call with first request
        if requests:
            return self.call_unary(service, method, requests[0])
        else:
            return self.call_unary(service, method, None)
    
    def __str__(self):
        return f"PtfGrpc(target={self.target}, plaintext={self.plaintext})"
    
    def __repr__(self):
        return self.__str__()