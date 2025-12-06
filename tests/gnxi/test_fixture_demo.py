"""
Demonstration of gRPC fixtures usage in real test scenarios.

This file shows how test authors would use the gRPC fixtures in practice,
providing examples of the clean interfaces available.
"""
import pytest
import logging

logger = logging.getLogger(__name__)


def test_grpc_fixture_basic_usage(ptf_grpc):
    """
    Example: Basic gRPC client usage with auto-configuration.
    
    This demonstrates how a test author would use the ptf_grpc fixture
    for direct gRPC operations without needing to configure connection details.
    """
    logger.info("Demo: Basic gRPC fixture usage")
    
    # Service discovery - works automatically
    services = ptf_grpc.list_services()
    assert "gnoi.system.System" in services
    
    # Direct gRPC calls with clean JSON interface
    time_response = ptf_grpc.call_unary("gnoi.system.System", "Time")
    assert "time" in time_response
    
    # Describe services for development/debugging
    system_info = ptf_grpc.describe("gnoi.system.System")
    assert "description" in system_info
    
    logger.info("✅ Basic gRPC fixture usage demonstrated")


def test_gnoi_fixture_high_level_interface(ptf_gnoi):
    """
    Example: High-level gNOI operations using the wrapper fixture.
    
    This demonstrates how the ptf_gnoi fixture provides clean Python
    method interfaces that hide gRPC complexity from test authors.
    """
    logger.info("Demo: High-level gNOI fixture usage")
    
    # Clean method call - no JSON manipulation required
    result = ptf_gnoi.system_time()
    
    # Automatic enhancements added by wrapper
    assert "time" in result  # Original gRPC response
    assert "formatted_time" in result  # Added by wrapper
    
    # Human-readable time format for easy assertions
    from datetime import datetime
    formatted_time = datetime.fromisoformat(result["formatted_time"])
    logger.info(f"Current device time: {formatted_time}")
    
    # Time should be recent (within last hour)
    import time
    now = time.time()
    device_time_seconds = int(result["time"]) / 1_000_000_000
    time_diff = abs(now - device_time_seconds)
    assert time_diff < 3600, f"Device time seems wrong: {time_diff} seconds difference"
    
    logger.info("✅ High-level gNOI fixture usage demonstrated")


def test_custom_grpc_configuration(ptf_grpc_custom, duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Example: Custom gRPC configuration for special test scenarios.
    
    This demonstrates how tests can customize gRPC client configuration
    when the auto-configured defaults are not sufficient.
    """
    logger.info("Demo: Custom gRPC configuration")
    
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    
    # Custom timeout for slow operations
    slow_client = ptf_grpc_custom(timeout=30.0)
    assert slow_client.timeout == 30.0
    
    # Custom headers for authentication/testing
    auth_client = ptf_grpc_custom()
    auth_client.add_header("x-test-id", "fixture-demo")
    assert "x-test-id" in auth_client.headers
    
    # Custom host/port for different services 
    explicit_client = ptf_grpc_custom(
        host=f"{duthost.mgmt_ip}:8080",
        plaintext=True,
        timeout=5.0
    )
    
    # All clients should work consistently
    services1 = slow_client.list_services()
    services2 = auth_client.list_services()
    services3 = explicit_client.list_services()
    
    assert "gnoi.system.System" in services1
    assert "gnoi.system.System" in services2  
    assert "gnoi.system.System" in services3
    
    logger.info("✅ Custom gRPC configuration demonstrated")


def test_mixed_fixture_usage(ptf_grpc, ptf_gnoi):
    """
    Example: Using multiple fixtures together for complex test scenarios.
    
    This demonstrates how tests can combine low-level and high-level
    fixtures when they need both direct gRPC access and convenience wrappers.
    """
    logger.info("Demo: Mixed fixture usage")
    
    # Use high-level wrapper for common operations
    gnoi_time = ptf_gnoi.system_time()
    assert "formatted_time" in gnoi_time
    
    # Use low-level client for custom/advanced operations
    # (Example: custom gRPC call that doesn't have a wrapper method)
    raw_time = ptf_grpc.call_unary("gnoi.system.System", "Time")
    assert "time" in raw_time
    
    # Verify both approaches get consistent results
    gnoi_time_ns = int(gnoi_time["time"])
    raw_time_ns = int(raw_time["time"])
    time_diff_ns = abs(gnoi_time_ns - raw_time_ns)
    
    # Should be within a few seconds of each other
    assert time_diff_ns < 5_000_000_000, f"Time inconsistency: {time_diff_ns / 1_000_000_000}s"
    
    # High-level wrapper preserves original data
    assert gnoi_time["time"] == raw_time["time"]
    
    logger.info("✅ Mixed fixture usage demonstrated")


@pytest.mark.parametrize("service", ["gnoi.system.System"])
def test_parameterized_grpc_testing(ptf_grpc, service):
    """
    Example: Parameterized testing with gRPC fixtures.
    
    This demonstrates how gRPC fixtures work seamlessly with pytest
    parameterization for testing multiple services or configurations.
    """
    logger.info(f"Demo: Parameterized testing for {service}")
    
    # Service should be available
    services = ptf_grpc.list_services()
    assert service in services, f"Service {service} not available"
    
    # Should be able to describe the service
    description = ptf_grpc.describe(service)
    assert "symbol" in description
    assert description["symbol"] == service
    
    logger.info(f"✅ Service {service} validated successfully")