"""
Development verification tests for gNOI client library implementation.

These tests verify each implementation step during development.
"""
import pytest
import logging

logger = logging.getLogger(__name__)


def test_step1(duthosts, enum_rand_one_per_hwsku_hostname):
    """Verify GNMIEnvironment fixes work with real deployment"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    from tests.common.helpers.gnmi_utils import GNMIEnvironment
    
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    
    # Test correct default port (should be 8080, not 50051/50052)
    logger.info(f"Detected gNMI port: {env.gnmi_port}")
    assert env.gnmi_port == 8080, f"Expected port 8080, got {env.gnmi_port}"
    
    # Test that configuration matches actual running service
    # telemetry process runs with: --port 8080 --noTLS --allow_no_client_auth
    assert hasattr(env, 'use_tls'), "GNMIEnvironment should have use_tls attribute"
    logger.info(f"Detected TLS setting: {env.use_tls}")
    assert env.use_tls == False, f"Expected plaintext (no TLS), got use_tls={env.use_tls}"
    
    # Test that container detection still works
    assert hasattr(env, 'gnmi_container'), "GNMIEnvironment should have gnmi_container attribute"
    assert hasattr(env, 'gnmi_process'), "GNMIEnvironment should have gnmi_process attribute"
    
    logger.info(f"✅ Step 1 verification successful:")
    logger.info(f"  - Port: {env.gnmi_port}")
    logger.info(f"  - TLS: {env.use_tls}")
    logger.info(f"  - Container: {env.gnmi_container}")
    logger.info(f"  - Process: {env.gnmi_process}")


def test_step1_config_db_changes(duthosts, enum_rand_one_per_hwsku_hostname):
    """Test that GNMIEnvironment correctly detects CONFIG_DB changes"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    from tests.common.helpers.gnmi_utils import GNMIEnvironment
    
    # Step 1: Test baseline (no CONFIG_DB config, should detect from process)
    logger.info("Testing baseline: no GNMI CONFIG_DB config")
    env1 = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    assert env1.gnmi_port == 8080, f"Baseline: Expected port 8080, got {env1.gnmi_port}"
    assert env1.use_tls == False, f"Baseline: Expected TLS=False, got {env1.use_tls}"
    
    try:
        # Step 2: Add GNMI config with different settings
        logger.info("Adding GNMI CONFIG_DB config with port 9999 and TLS=true")
        duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" port 9999')
        duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" client_auth true')
        
        # Verify CONFIG_DB was set
        port_result = duthost.shell('sonic-db-cli CONFIG_DB hget "GNMI|gnmi" port')
        auth_result = duthost.shell('sonic-db-cli CONFIG_DB hget "GNMI|gnmi" client_auth')
        assert port_result['stdout'] == '9999', f"CONFIG_DB port not set correctly: {port_result['stdout']}"
        assert auth_result['stdout'] == 'true', f"CONFIG_DB client_auth not set correctly: {auth_result['stdout']}"
        
        # Step 3: Test that GNMIEnvironment picks up CONFIG_DB settings
        logger.info("Testing CONFIG_DB detection")
        env2 = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
        assert env2.gnmi_port == 9999, f"CONFIG_DB: Expected port 9999, got {env2.gnmi_port}"
        assert env2.use_tls == True, f"CONFIG_DB: Expected TLS=True, got {env2.use_tls}"
        
        # Step 4: Test different CONFIG_DB settings
        logger.info("Updating CONFIG_DB config with port 7777 and TLS=false")
        duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" port 7777')
        duthost.shell('sonic-db-cli CONFIG_DB hset "GNMI|gnmi" client_auth false')
        
        env3 = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
        assert env3.gnmi_port == 7777, f"Updated CONFIG_DB: Expected port 7777, got {env3.gnmi_port}"
        assert env3.use_tls == False, f"Updated CONFIG_DB: Expected TLS=False, got {env3.use_tls}"
        
        logger.info("All CONFIG_DB configuration tests passed!")
        
    finally:
        # Step 5: Cleanup - remove CONFIG_DB settings
        logger.info("Cleaning up CONFIG_DB GNMI configuration")
        duthost.shell('sonic-db-cli CONFIG_DB hdel "GNMI|gnmi" port', module_ignore_errors=True)
        duthost.shell('sonic-db-cli CONFIG_DB hdel "GNMI|gnmi" client_auth', module_ignore_errors=True)
        
        # Verify cleanup worked - should fall back to process detection (8080, False)
        env4 = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
        assert env4.gnmi_port == 8080, f"Cleanup: Expected fallback to port 8080, got {env4.gnmi_port}"
        assert env4.use_tls == False, f"Cleanup: Expected fallback to TLS=False, got {env4.use_tls}"
        
        logger.info("CONFIG_DB cleanup verification passed!")


def test_step2(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost):
    """Verify PtfGrpc base class with auto-configuration"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    from tests.common.helpers.gnmi_utils import GNMIEnvironment
    from tests.common.ptf_grpc import PtfGrpc
    
    # Test manual configuration
    logger.info("Testing manual PtfGrpc configuration")
    client = PtfGrpc(ptfhost, f"{duthost.mgmt_ip}:8080", plaintext=True)
    
    # Test service discovery
    logger.info("Testing service discovery")
    services = client.list_services()
    logger.info(f"Available services: {services}")
    
    # Verify gNOI system service is available
    assert "gnoi.system.System" in services, f"gnoi.system.System not found in services: {services}"
    
    # Test service description
    logger.info("Testing service description")
    system_desc = client.describe("gnoi.system.System")
    assert "symbol" in system_desc
    assert system_desc["symbol"] == "gnoi.system.System"
    
    # Test basic gNOI call
    logger.info("Testing basic gNOI System.Time call")
    time_response = client.call_unary("gnoi.system.System", "Time")
    assert "time" in time_response, f"Expected 'time' field in response: {time_response}"
    
    # Test auto-configuration with GNMIEnvironment
    logger.info("Testing auto-configuration with GNMIEnvironment")
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    auto_client = PtfGrpc(ptfhost, env, duthost=duthost)
    
    # Verify auto-configured client works the same
    auto_services = auto_client.list_services()
    assert "gnoi.system.System" in auto_services, f"Auto-config: gnoi.system.System not found: {auto_services}"
    
    auto_time_response = auto_client.call_unary("gnoi.system.System", "Time") 
    assert "time" in auto_time_response, f"Auto-config: Expected 'time' field: {auto_time_response}"
    
    logger.info("✅ Step 2 verification successful:")
    logger.info(f"  - Manual config: {client}")
    logger.info(f"  - Auto config: {auto_client}")
    logger.info(f"  - Services discovered: {len(services)}")
    logger.info(f"  - System.Time working: {bool(time_response.get('time'))}")


def test_step3(duthosts, enum_rand_one_per_hwsku_hostname, ptfhost):
    """Verify connection configuration and error handling"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    from tests.common.ptf_grpc import PtfGrpc, GrpcConnectionError, GrpcTimeoutError
    import pytest
    
    # Test connection validation with valid target
    logger.info("Testing connection validation")
    client = PtfGrpc(ptfhost, f"{duthost.mgmt_ip}:8080", plaintext=True)
    
    # Test successful connection
    logger.info("Testing successful connection")
    assert client.test_connection() == True
    
    # Test timeout configuration  
    logger.info("Testing timeout configuration")
    original_timeout = client.timeout
    client.configure_timeout(5.0)
    assert client.timeout == 5.0
    
    # Verify client still works with new timeout
    services = client.list_services()
    assert "gnoi.system.System" in services
    
    # Test header configuration
    logger.info("Testing header configuration")
    client.add_header("x-test-header", "test-value")
    assert "x-test-header" in client.headers
    assert client.headers["x-test-header"] == "test-value"
    
    # Verify client still works with headers
    time_response = client.call_unary("gnoi.system.System", "Time")
    assert "time" in time_response
    
    # Test verbose mode
    logger.info("Testing verbose mode")
    client.set_verbose(True)
    assert client.verbose == True
    
    # Test connection error handling with invalid target
    logger.info("Testing connection error handling") 
    bad_client = PtfGrpc(ptfhost, "invalid.host:9999", plaintext=True)
    
    # Should raise either GrpcConnectionError or GrpcTimeoutError for invalid host
    with pytest.raises((GrpcConnectionError, GrpcTimeoutError)) as exc_info:
        bad_client.test_connection()
    
    assert any(term in str(exc_info.value).lower() for term in ["connection failed", "timed out", "deadline exceeded"])
    
    # Test timeout error with very short timeout
    logger.info("Testing timeout error handling")
    timeout_client = PtfGrpc(ptfhost, f"{duthost.mgmt_ip}:8080", plaintext=True) 
    timeout_client.configure_timeout(0.001)  # 1ms - should timeout
    
    with pytest.raises(GrpcTimeoutError) as exc_info:
        timeout_client.list_services()
    
    assert "timed out" in str(exc_info.value).lower()
    
    logger.info("✅ Step 3 verification successful:")
    logger.info(f"  - Connection validation: working")
    logger.info(f"  - Timeout configuration: {original_timeout}s -> 5.0s")
    logger.info(f"  - Header support: {len(client.headers)} headers")
    logger.info(f"  - Error handling: connection and timeout errors caught")
    logger.info(f"  - Verbose mode: configurable")