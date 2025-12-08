"""
Simple integration tests for gNOI System service.

All tests automatically run with TLS server configuration by default.
Users don't need to worry about TLS configuration.
"""
import pytest
import logging

# Import fixtures
from tests.common.fixtures.grpc_fixtures import ptf_grpc, ptf_gnoi, setup_gnoi_tls_server

logger = logging.getLogger(__name__)

# Enable TLS fixture by default for all tests in this module
pytestmark = pytest.mark.usefixtures("setup_gnoi_tls_server")


def test_system_time(ptf_gnoi):
    """Test System.Time RPC with TLS enabled by default."""
    result = ptf_gnoi.system_time()
    assert "time" in result
    assert "formatted_time" in result
    logger.info(f"System time: {result['formatted_time']}")