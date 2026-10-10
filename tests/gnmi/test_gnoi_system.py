"""
Integration tests for gNOI System and FactoryReset services.

Tests run with TLS by default. Opt-in to dual transport (TLS + UDS)
via the parametrize decorator on individual tests.
"""
import pytest
import logging

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.assertions import pytest_assert
from tests.gnmi.helper import GNOI_ROLE_CASES, verify_gnoi_role_access

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]


@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize("role,error_pattern", GNOI_ROLE_CASES)
def test_gnoi_factory_reset_authorization(gnmi_tls, role, error_pattern):  # noqa: F811
    """FactoryReset must deny readers and allow writers to reach the backend."""
    # Use the host service's unsupported zero-fill request, never a normal reset.
    response = verify_gnoi_role_access(
        gnmi_tls, role,
        lambda: gnmi_tls.grpc.call_unary("gnoi.factory_reset.FactoryReset", "Start",
                                         {"factoryOs": True, "zeroFill": True}),
        error_pattern,
    )
    if not error_pattern:
        detail = response.get("resetError", {}).get("detail", "")
        pytest_assert("zero_fill operation is currently unsupported" in detail, response)


@pytest.mark.parametrize("gnmi_tls", ["tls", "uds"], indirect=True)
def test_system_time(gnmi_tls):  # noqa: F811
    """Test System.Time RPC works over both TLS and UDS transports."""
    result = gnmi_tls.gnoi.system_time()
    assert "time" in result
    assert isinstance(result["time"], int)
    assert result["time"] > 0
    logger.info("System time via %s: %d ns", gnmi_tls.transport, result["time"])
