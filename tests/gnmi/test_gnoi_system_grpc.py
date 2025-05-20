import pytest
import logging
import time

from tests.gnmi.grpc_utils import get_gnoi_system_stubs

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_memory_utilization
]


"""
This module contains tests for the gNOI System Services, using gRPC python API.
"""


system_pb2_grpc, system_pb2 = get_gnoi_system_stubs()


def test_gnoi_system_time(grpc_channel):
    """
    Verify the gNOI System Time API returns the current system time in valid JSON format.
    """
    # Use the shared gRPC channel
    stub = system_pb2_grpc.SystemStub(grpc_channel)

    # Create and send request
    request = system_pb2.TimeRequest()
    response = stub.Time(request)

    # Log the response
    logging.info("Received response: %s", response)

    # Assert the time falls into a reasonable interval
    current_time_ns = int(time.time() * 1e9)
    reasonable_interval_ns = 60 * 1e9  # 60 seconds in nanoseconds

    assert (
        abs(response.time - current_time_ns) < reasonable_interval_ns
    ), f"System time {response.time} is not within the reasonable interval of current time {current_time_ns}"
