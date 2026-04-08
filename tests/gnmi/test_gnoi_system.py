"""
Simple integration tests for gNOI System service.

All tests automatically run with TLS server configuration by default.
Users don't need to worry about TLS configuration.
"""
import pytest
import logging

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]


def test_system_time(gnmi_tls):  # noqa: F811
    """Test System.Time RPC with TLS enabled by default."""
    result = gnmi_tls.gnoi.system_time()
    assert "time" in result
    assert isinstance(result["time"], int)
    logger.info(f"System time: {result['time']} nanoseconds since epoch")
