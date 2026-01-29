"""
Simple integration tests for gNOI System service.

All tests automatically run with TLS server configuration by default.
Users don't need to worry about TLS configuration.
"""
import pytest
import logging

# Import fixtures to ensure pytest discovers them
from tests.common.fixtures.grpc_fixtures import (  # noqa: F401
    setup_gnoi_tls_server, ptf_gnoi, ptf_grpc
)

logger = logging.getLogger(__name__)

# Enable TLS fixture by default for all tests in this module
pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.usefixtures("setup_gnoi_tls_server")
]


def test_system_time(ptf_gnoi):  # noqa: F811
    """Test System.Time RPC with TLS enabled by default."""
    result = ptf_gnoi.system_time()
    assert "time" in result
    assert isinstance(result["time"], int)
    logger.info(f"System time: {result['time']} nanoseconds since epoch")
