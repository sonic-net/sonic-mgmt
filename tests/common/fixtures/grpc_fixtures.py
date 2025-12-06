"""
Pytest fixtures for gRPC clients (gNOI, gNMI, etc.)

This module provides pytest fixtures for easy access to gRPC clients with
automatic configuration discovery, making it simple to write gRPC-based tests.
"""
import pytest
import logging

logger = logging.getLogger(__name__)


@pytest.fixture
def ptf_grpc(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Auto-configured gRPC client using GNMIEnvironment for discovery.
    
    This fixture provides a ready-to-use PtfGrpc client that automatically
    detects the correct gRPC endpoint configuration from the DUT.
    
    Args:
        ptfhost: PTF host fixture for command execution
        duthosts: DUT hosts fixture
        enum_rand_one_per_hwsku_hostname: Random DUT selection fixture
        
    Returns:
        PtfGrpc: Configured gRPC client ready for use
        
    Example:
        def test_grpc_services(ptf_grpc):
            services = ptf_grpc.list_services()
            assert "gnoi.system.System" in services
    """
    from tests.common.helpers.gnmi_utils import GNMIEnvironment
    from tests.common.ptf_grpc import PtfGrpc
    
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    
    # Auto-configure using GNMIEnvironment
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    client = PtfGrpc(ptfhost, env, duthost=duthost)
    
    logger.info(f"Created auto-configured gRPC client: {client}")
    return client


@pytest.fixture  
def ptf_gnoi(ptf_grpc):
    """
    gNOI-specific client using auto-configured gRPC client.
    
    This fixture provides a high-level PtfGnoi wrapper that exposes clean
    Python method interfaces for gNOI operations, hiding gRPC complexity.
    
    Args:
        ptf_grpc: Auto-configured gRPC client fixture
        
    Returns:
        PtfGnoi: High-level gNOI client wrapper
        
    Example:
        def test_system_time(ptf_gnoi):
            result = ptf_gnoi.system_time()
            assert "time" in result
            assert "formatted_time" in result
    """
    from tests.common.ptf_gnoi import PtfGnoi
    
    gnoi_client = PtfGnoi(ptf_grpc)
    logger.info(f"Created gNOI wrapper: {gnoi_client}")
    return gnoi_client


@pytest.fixture
def ptf_grpc_custom(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Factory fixture for custom gRPC client configuration.
    
    This fixture returns a factory function that allows creating gRPC clients
    with custom configuration when auto-detection is not sufficient.
    
    Args:
        ptfhost: PTF host fixture for command execution
        duthosts: DUT hosts fixture  
        enum_rand_one_per_hwsku_hostname: Random DUT selection fixture
        
    Returns:
        Callable: Factory function for creating custom gRPC clients
        
    Example:
        def test_custom_grpc(ptf_grpc_custom, duthost):
            # Custom TLS configuration
            tls_client = ptf_grpc_custom(
                host=f"{duthost.mgmt_ip}:8080", 
                plaintext=False,
                cert_path="/path/to/cert.pem"
            )
            
            # Custom timeout
            fast_client = ptf_grpc_custom(timeout=1.0)
            
            services = fast_client.list_services()
    """
    from tests.common.helpers.gnmi_utils import GNMIEnvironment
    from tests.common.ptf_grpc import PtfGrpc
    
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    
    def _create_custom_client(host=None, port=None, plaintext=None, timeout=None, **kwargs):
        """
        Create a custom gRPC client with specified configuration.
        
        Args:
            host: Target host (defaults to DUT mgmt IP)
            port: Target port (defaults to auto-detected port)  
            plaintext: Use plaintext connection (defaults to auto-detected)
            timeout: Connection timeout in seconds
            **kwargs: Additional PtfGrpc configuration options
            
        Returns:
            PtfGrpc: Configured gRPC client
        """
        # Use GNMIEnvironment for defaults if specific values not provided
        if host is None or port is None:
            env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
            if host is None:
                host = duthost.mgmt_ip
            if port is None:
                port = env.gnmi_port
            if plaintext is None:
                plaintext = not env.use_tls
        
        # Construct target string
        if ':' not in str(host):
            target = f"{host}:{port}"
        else:
            target = str(host)
        
        # Create client with custom configuration
        client = PtfGrpc(ptfhost, target, plaintext=plaintext, **kwargs)
        
        # Apply additional configuration
        if timeout is not None:
            client.configure_timeout(timeout)
            
        logger.info(f"Created custom gRPC client: {client}")
        return client
    
    return _create_custom_client


@pytest.fixture
def ptf_gnmi(ptf_grpc):
    """
    gNMI-specific client using auto-configured gRPC client.
    
    This fixture provides a gNMI wrapper for future gNMI operations.
    Currently returns the base gRPC client until a dedicated gNMI wrapper is needed.
    
    Args:
        ptf_grpc: Auto-configured gRPC client fixture
        
    Returns:
        PtfGrpc: gRPC client configured for gNMI operations
        
    Note:
        This fixture is a placeholder for future gNMI-specific functionality.
        For now, it returns the base gRPC client which can call gNMI services directly.
        
    Example:
        def test_gnmi_get(ptf_gnmi):
            # Use generic gRPC interface for gNMI calls
            response = ptf_gnmi.call_unary("gnmi.gNMI", "Get", {
                "path": [{"elem": [{"name": "system"}, {"name": "state"}]}]
            })
    """
    # For now, return the base gRPC client
    # TODO: Create dedicated PtfGnmi wrapper class when needed
    logger.info("Created gNMI client (using base gRPC client)")
    return ptf_grpc