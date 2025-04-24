import pytest
import logging

from tests.common.reboot import wait_for_startup
from tests.gnmi.grpc_utils import get_gnoi_system_stubs

pytestmark = [
    pytest.mark.topology("any"),
]


"""
This module contains tests for the gNOI System Services, using gRPC python API.
"""


system_pb2_grpc, system_pb2 = get_gnoi_system_stubs()


def test_gnoi_system_reboot_cold(duthosts, rand_one_dut_hostname, localhost, grpc_channel):
    """
    Verify the gNOI System Reboot API functions correctly.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Use the shared gRPC channel
    stub = system_pb2_grpc.SystemStub(grpc_channel)

    # Create and send reboot request
    request = system_pb2.RebootRequest(
        method=system_pb2.RebootMethod.COLD,
        delay=0,
        message="Test reboot request",
        force=False
    )

    logging.info("Sending reboot request: %s", request)
    response = stub.Reboot(request)

    # Log the response
    logging.info("Received reboot response: %s", response)

    # A successful response means the reboot was initiated successfully
    assert response is not None, "Reboot request failed to get a response"

    # Wait for the DUT to reboot and come back online
    logging.info("Waiting for DUT to reboot...")
    wait_for_startup(duthost, localhost, 0, 300)
