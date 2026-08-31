"""gNMI certificate-revocation tests using the managed TLS fixture."""

import logging

import grpc
import pytest

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.pygnmi_client import PygnmiClientError
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)
REVOKED_MESSAGE = "desc = Peer certificate revoked"
VNET_NAME = "gnmi-crl-revoked"
VNET_KEY = "DASH_VNET_TABLE:{}".format(VNET_NAME)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures("setup_gnmi_ntp_client_server"),
]


def _rpc_status(error):
    """Return the gRPC status preserved by pygnmi, when available."""
    current = error
    while current is not None:
        if isinstance(current, grpc.RpcError):
            return current.code()
        current = getattr(current, "orig_exc", None) or current.__cause__
    return None


@pytest.mark.parametrize("gnmi_tls", ["tls_crl"], indirect=True)
def test_gnmi_authorize_failed_with_revoked_cert(
    gnmi_tls, rand_one_dut_hostname  # noqa: F811
):
    """Reject an APPL_DB Set authenticated by a CRL-revoked certificate."""
    marker = gnmi_tls.mark_gnmi_log()
    payload = {
        VNET_NAME: {
            "vni": "1000",
            "guid": "559c6ce8-26ab-4193-b946-ccc6e8f930b2",
        }
    }
    client = gnmi_tls.revoked_client()
    errors = []
    statuses = []
    revoked_logged = False

    try:
        for _ in range(3):
            try:
                client.set(update=[(
                    "sonic-db:APPL_DB/localhost/DASH_VNET_TABLE",
                    payload,
                )])
            except PygnmiClientError as error:
                errors.append(str(error))
                statuses.append(_rpc_status(error))
            else:
                pytest.fail("Revoked client certificate unexpectedly wrote APPL_DB")

            revoked_logged = wait_until(
                10,
                1,
                0,
                lambda: REVOKED_MESSAGE in gnmi_tls.gnmi_log_since(marker),
            )
            if revoked_logged:
                break
    finally:
        client.close()
        gnmi_tls.duthost.shell(
            "sonic-db-cli APPL_DB del '{}'".format(VNET_KEY),
            module_ignore_errors=True,
        )

    assert grpc.StatusCode.UNAUTHENTICATED in statuses, (
        "Expected Unauthenticated status from revoked certificate, got: "
        "statuses={}, errors={}".format(statuses, errors)
    )
    assert revoked_logged, (
        "Expected revoked-certificate diagnostic in new /var/log/gnmi.log bytes"
    )
