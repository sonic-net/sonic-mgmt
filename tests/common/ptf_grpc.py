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
        
        # Default grpcurl options
        self.default_timeout = 10.0  # seconds as float
        self.max_msg_size = 100 * 1024 * 1024  # 100MB in bytes
    
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
            "-connect-timeout", str(self.default_timeout),
            "-max-msg-sz", str(self.max_msg_size),
            "-format", "json"
        ])
        
        # Add extra arguments
        if extra_args:
            cmd.extend(extra_args)
        
        # Add target
        cmd.append(self.target)
        
        # Add service method if specified
        if service_method:
            cmd.append(service_method)
        
        return cmd
    
    def list_services(self) -> List[str]:
        """
        List all available gRPC services.
        
        Returns:
            List of service names
        """
        cmd = self._build_grpcurl_cmd(service_method="list")
        
        logger.debug(f"Executing: {' '.join(cmd)}")
        result = self.ptfhost.shell(' '.join(cmd), module_ignore_errors=True)
        
        if result['rc'] != 0:
            raise PtfGrpcError(f"Failed to list services: {result['stderr']}")
        
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
        """
        cmd = self._build_grpcurl_cmd(service_method=f"describe {symbol}")
        
        logger.debug(f"Executing: {' '.join(cmd)}")
        result = self.ptfhost.shell(' '.join(cmd), module_ignore_errors=True)
        
        if result['rc'] != 0:
            raise PtfGrpcError(f"Failed to describe {symbol}: {result['stderr']}")
        
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
        """
        service_method = f"{service}/{method}"
        cmd = self._build_grpcurl_cmd(service_method=service_method)
        
        # Prepare request data
        request_data = ""
        if request:
            if isinstance(request, dict):
                request_data = json.dumps(request)
            else:
                request_data = str(request)
        
        # Build full command
        if request_data:
            full_cmd = f"echo '{request_data}' | {' '.join(cmd)}"
        else:
            full_cmd = f"echo '{{}}' | {' '.join(cmd)}"
        
        logger.debug(f"Executing: {full_cmd}")
        result = self.ptfhost.shell(full_cmd, module_ignore_errors=True)
        
        if result['rc'] != 0:
            raise PtfGrpcError(f"Failed to call {service_method}: {result['stderr']}")
        
        try:
            response = json.loads(result['stdout'].strip())
            logger.debug(f"Response from {service_method}: {response}")
            return response
        except json.JSONDecodeError as e:
            raise PtfGrpcError(f"Failed to parse response from {service_method}: {e}")
    
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