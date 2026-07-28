"""CRL revoked-certificate authorization test for the native gRPC fixture."""

import logging

import pytest

from tests.common.grpc_test_environment import GrpcTestSpec
from tests.common.pygnmi_client import PygnmiClientCallError, PygnmiClientConnectionError
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
]


@pytest.fixture(scope="module")
def grpc_spec():
    """Return a CRL-enabled gRPC environment spec for this module."""
    return GrpcTestSpec(enable_crl=True)


def test_gnmi_authorize_failed_with_revoked_cert(
    _grpc_environment,
):
    """gNMI Set MUST be rejected with Unauthenticated when the client cert is CRL-revoked."""
    vnet_payload = {"Vnet1": {"vni": "1000", "guid": "559c6ce8-26ab-4193-b946-ccc6e8f930b2"}}

    retry = 3
    msg = ""
    gnmi_log = ""
    while retry > 0:
        retry -= 1
        msg = ""
        client = _grpc_environment.revoked_client()
        try:
            client.set(update=[("/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE", vnet_payload)])
        except (PygnmiClientCallError, PygnmiClientConnectionError) as exc:
            logger.info("gnmi set failed (expected): %s", exc)
            msg = str(exc)
        finally:
            client.close()

        wait_until(
            10,
            1,
            0,
            lambda: "desc = Peer certificate revoked"
            in _grpc_environment.gnmi_log(),
        )
        gnmi_log = _grpc_environment.gnmi_log()
        if "desc = Peer certificate revoked" in gnmi_log:
            break

    assert "unauthenticated" in msg.lower(), (
        "'Unauthenticated' error message not found in gNMI response. "
        "- Actual message: '{}'"
    ).format(msg)

    assert "desc = Peer certificate revoked" in gnmi_log, (
        "'desc = Peer certificate revoked' message not found in gNMI log. "
        "- Actual gNMI log: '{}'"
    ).format(gnmi_log)
