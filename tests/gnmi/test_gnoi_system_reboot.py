import pytest
import logging
import grpc

from tests.common.reboot import wait_for_startup
from tests.common.helpers.gnmi_utils import GNMIEnvironment
from tests.gnmi.grpc_utils import get_gnoi_system_stubs

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
]


"""
This module contains tests for the gNOI System Services, using gRPC python API.
"""


system_pb2_grpc, system_pb2 = get_gnoi_system_stubs()


def test_gnoi_system_reboot_cold(duthosts, rand_one_dut_hostname, localhost):
    """
    Verify the gNOI System Reboot API functions correctly.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Get DUT gRPC server address and port
    ip = duthost.mgmt_ip
    env = GNMIEnvironment(duthost, GNMIEnvironment.GNMI_MODE)
    port = env.gnmi_port
    target = f"{ip}:{port}"

    # Load the TLS certificates
    with open("gnmiCA.pem", "rb") as f:
        root_certificates = f.read()
    with open("gnmiclient.crt", "rb") as f:
        client_certificate = f.read()
    with open("gnmiclient.key", "rb") as f:
        client_key = f.read()

    # Create SSL credentials
    credentials = grpc.ssl_channel_credentials(
        root_certificates=root_certificates,
        private_key=client_key,
        certificate_chain=client_certificate,
    )

    # Create gRPC channel
    logging.info("Creating gRPC secure channel to %s", target)

    with grpc.secure_channel(target, credentials) as channel:
        try:
            grpc.channel_ready_future(channel).result(timeout=10)
            logging.info("gRPC channel is ready")
        except grpc.FutureTimeoutError as e:
            logging.error("Error: gRPC channel not ready: %s", e)
            pytest.fail("Failed to connect to gRPC server")

        # Create gRPC stub
        stub = system_pb2_grpc.SystemStub(channel)

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
