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


def test_gnoi_system_time(grpc_channel, duthosts, rand_one_dut_hostname):
    """
    Verify the gNOI System Time API returns the current system time in valid JSON format.
    """
    duthost = duthosts[rand_one_dut_hostname]
    
    # Use the shared gRPC channel
    stub = system_pb2_grpc.SystemStub(grpc_channel)

    # Get device time in nanoseconds using shell command
    device_time_result = duthost.shell("date +%s%N", module_ignore_errors=True)
    device_time_ns = int(device_time_result["stdout"].strip())

    # Create and send request
    request = system_pb2.TimeRequest()
    response = stub.Time(request)

    # Log the response
    logging.info("Received response: %s", response)
    logging.info("Device time from shell: %d", device_time_ns)

    # Assert the gNOI time is close to device shell time
    reasonable_interval_ns = 60 * 1e9  # 60 seconds in nanoseconds

    assert (
        abs(response.time - device_time_ns) < reasonable_interval_ns
    ), f"gNOI time {response.time} differs from device time {device_time_ns} by more than {reasonable_interval_ns}ns"
