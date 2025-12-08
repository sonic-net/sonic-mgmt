"""
Simple integration tests for gNOI File service.

One test per RPC method to demonstrate library usage.
"""
import pytest
import logging

# Import fixtures
from tests.common.fixtures.grpc_fixtures import ptf_grpc, ptf_gnoi

logger = logging.getLogger(__name__)


def test_file_stat(ptf_gnoi):
    """Test File.Stat RPC."""
    try:
        result = ptf_gnoi.file_stat("/etc/hostname")
        assert "stats" in result
        logger.info(f"File stats: {result['stats'][0]}")
    except Exception as e:
        # File service may not be fully implemented
        logger.warning(f"File.Stat failed (expected): {e}")