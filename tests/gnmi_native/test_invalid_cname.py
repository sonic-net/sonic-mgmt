"""Invalid client CN authorization test for the native gRPC fixture."""

import logging

import pytest

from tests.common.helpers.gnmi_utils import (
    add_gnmi_client_common_name,
    del_gnmi_client_common_name,
    dump_gnmi_log,
)
from tests.common.pygnmi_client import PygnmiClientCallError, PygnmiClientConnectionError

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer,
    pytest.mark.disable_memory_utilization,
]


@pytest.fixture(scope="module")
def setup_invalid_client_cert_cname(duthosts, enum_rand_one_per_hwsku_frontend_hostname, _grpc_environment):
    """Swap the CN mapping so the gNMI server rejects the standard client cert."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    del_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
    add_gnmi_client_common_name(duthost, "invalid.cname")

    keys = duthost.shell('sudo sonic-db-cli CONFIG_DB keys GNMI*')["stdout_lines"]
    logger.debug("GNMI client cert keys: %s", keys)

    yield

    del_gnmi_client_common_name(duthost, "invalid.cname")
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")


def gnmi_create_vnet_native(duthost, client):
    """Issue a native Set against APPL_DB/DASH_VNET_TABLE; return (error_msg, gnmi_log)."""
    vnet_payload = {"Vnet1": {"vni": "1000", "guid": "559c6ce8-26ab-4193-b946-ccc6e8f930b2"}}
    error_message = ""
    try:
        client.set(update=[("/sonic-db:APPL_DB/localhost/DASH_VNET_TABLE", vnet_payload)])
    except (PygnmiClientCallError, PygnmiClientConnectionError) as exc:
        logger.info("gnmi set failed (expected): %s", exc)
        error_message = str(exc)

    gnmi_log = dump_gnmi_log(duthost)
    return error_message, gnmi_log


def test_gnmi_authorize_failed_with_invalid_cname(
    duthosts,
    enum_rand_one_per_hwsku_frontend_hostname,
    _grpc_environment,
    setup_invalid_client_cert_cname,
):
    """gNMI Set MUST be rejected with Unauthenticated when the client CN has no mapping."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    client = _grpc_environment.gnmi_client(connect=False)
    try:
        msg, gnmi_log = gnmi_create_vnet_native(duthost, client)
    finally:
        client.close()

    assert "unauthenticated" in msg.lower(), (
        "'Unauthenticated' error message not found in gNMI response. "
        "- Actual message: '{}'"
    ).format(msg)

    assert "Failed to retrieve cert common name mapping" in gnmi_log, (
        "'Failed to retrieve cert common name mapping' not found in gNMI log. "
        "- Actual gNMI log: '{}'"
    ).format(gnmi_log)
