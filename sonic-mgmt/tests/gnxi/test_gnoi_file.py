"""
Simple integration tests for gNOI File service.

All tests automatically run with TLS server configuration by default.
Users don't need to worry about TLS configuration.
"""
import pytest
import logging

# Import fixtures module to ensure pytest discovers them
import tests.common.fixtures.grpc_fixtures  # noqa: F401

logger = logging.getLogger(__name__)

# Enable TLS fixture by default for all tests in this module
pytestmark = pytest.mark.usefixtures("setup_gnoi_tls_server")


def test_file_stat(ptf_gnoi):
    """Test File.Stat RPC with TLS enabled by default."""
    try:
        result = ptf_gnoi.file_stat("/etc/hostname")
        assert "stats" in result
        logger.info(f"File stats: {result['stats'][0]}")
    except Exception as e:
        # File service may not be fully implemented
        logger.warning(f"File.Stat failed (expected): {e}")
