"""
Integration tests for gNOI System service.

Tests run with TLS by default. Opt-in to dual transport (TLS + UDS)
via the parametrize decorator on individual tests.
"""
import pytest
import logging

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]


@pytest.mark.parametrize("gnmi_tls", ["tls", "uds"], indirect=True)
def test_system_time(gnmi_tls):  # noqa: F811
    """Test System.Time RPC works over both TLS and UDS transports."""
    result = gnmi_tls.gnoi.system_time()
    assert "time" in result
    assert isinstance(result["time"], int)
    assert result["time"] > 0
    logger.info("System time via %s: %d ns", gnmi_tls.transport, result["time"])
