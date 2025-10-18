"""
Test gNOI System Service

This module tests gNOI System service RPCs including Time, Reboot, etc.
"""
import pytest
import logging
import time as time_module

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)


def test_system_time(grpc_client):
    """
    Test gNOI System.Time RPC.

    This test verifies:
    - grpcurl is downloaded and installed on vmhost
    - gNOI System.Time RPC can be called successfully
    - Response contains valid Unix timestamp
    - Timestamp is reasonable (within 1 year of current time)
    """
    logger.info("Calling System.Time RPC")

    # Call System.Time (unary RPC with empty request)
    # Full service path: gnoi.system.System
    response = grpc_client.call_unary("gnoi.system.System", "Time")

    logger.info(f"System.Time response: {response}")

    # Verify response has time field
    assert "time" in response, "Response should contain 'time' field"

    # Extract timestamp (Unix nanoseconds)
    time_ns = int(response["time"])
    time_s = time_ns / 1_000_000_000

    logger.info(f"Device time: {time_s} seconds since epoch")

    # Verify timestamp is reasonable (within 1 year of current time)
    current_time = time_module.time()
    time_diff = abs(current_time - time_s)

    assert time_diff < 365 * 24 * 3600, \
        f"Device time differs from current time by {time_diff} seconds (> 1 year)"

    logger.info(f"✓ System.Time RPC successful - device time is reasonable")
