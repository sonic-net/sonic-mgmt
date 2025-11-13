import pytest
import logging

from tests.gnmi.grpc_utils import get_gnoi_system_stubs, create_grpc_channel

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_memory_utilization
]


"""
This module contains tests for the gNOI System Services, using gRPC python API.
"""


system_pb2_grpc, system_pb2 = get_gnoi_system_stubs()


def test_gnoi_system_time(duthosts, rand_one_dut_hostname):
    """
    Verify the gNOI System Time API returns the current system time.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Get device time in seconds first (before gRPC operations)
    device_time_result = duthost.shell("date +%s", module_ignore_errors=True)
    device_time_s = int(device_time_result["stdout"].strip())
    device_time_ns = device_time_s * int(1e9)

    # Create gRPC channel (no longer a fixture to avoid SSL state sharing)
    channel = create_grpc_channel(duthost)

    try:
        # Create gRPC stub
        stub = system_pb2_grpc.SystemStub(channel)

        # Create and send request
        request = system_pb2.TimeRequest()
        response = stub.Time(request)

        # Log the response
        logging.info("Received response: %s", response)
        logging.info("Device time from shell: %d", device_time_ns)

        # Assert the gNOI time is close to device shell time
        reasonable_interval_ns = 60 * 1e9  # 60 seconds in nanoseconds

        time_diff = abs(response.time - device_time_ns)
        assert time_diff < reasonable_interval_ns, (
            f"gNOI time {response.time} differs from device time "
            f"{device_time_ns} by {time_diff}ns (max: {reasonable_interval_ns}ns)"
        )
    finally:
        # Always close the channel to avoid resource leaks
        channel.close()
