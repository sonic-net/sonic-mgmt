"""
Simple integration tests for gNOI System service.

One test per RPC method to demonstrate library usage.
"""
import pytest
import logging

# Import fixtures
from tests.common.fixtures.grpc_fixtures import ptf_grpc, ptf_gnoi

logger = logging.getLogger(__name__)


def test_system_time(ptf_gnoi):
    """Test System.Time RPC."""
    result = ptf_gnoi.system_time()
    assert "time" in result
    assert "formatted_time" in result
    logger.info(f"System time: {result['formatted_time']}")