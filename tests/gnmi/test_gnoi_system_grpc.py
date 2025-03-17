import pytest
import logging
import grpc
import time
import os
import sys

from tests.common.helpers.gnmi_utils import GNMIEnvironment

pytestmark = [pytest.mark.topology("any")]


"""
This module contains tests for the gNOI System Services, using gRPC python API.
"""


def _get_gnoi_stubs():
    PROTO_ROOT = "gnmi/protos"
    sys.path.append(os.path.abspath(PROTO_ROOT))
    from gnoi.system import system_pb2_grpc, system_pb2
    return system_pb2_grpc, system_pb2


system_pb2_grpc, system_pb2 = _get_gnoi_stubs()


def test_gnoi_system_time(duthosts, rand_one_dut_hostname):
    """
    Verify the gNOI System Time API returns the current system time in valid JSON format.
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
