import pytest
import logging

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.pygnmi_client import PygnmiClientError

logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.usefixtures('rand_one_dut_hostname')
]


def test_gnmi_authorize_passed_with_valid_cname(gnmi_tls):  # noqa: F811
    """A CA-signed client with a mapped CN must return gNMI capabilities."""
    result = gnmi_tls.pygnmi_client.capabilities()
    assert isinstance(result, dict), "Expected a Capabilities response, got {!r}".format(result)
    assert result.get("gnmi_version"), "Missing gNMI version in Capabilities response: {!r}".format(result)
    assert result.get("supported_encodings"), \
        "Missing supported encodings in Capabilities response: {!r}".format(result)
    logger.info(
        "Valid-CN authorization succeeded on %s: gnmi_version=%s, supported_encodings=%s",
        gnmi_tls.duthost.hostname, result["gnmi_version"], result["supported_encodings"]
    )


def test_gnmi_authorize_failed_with_invalid_cname(gnmi_tls):  # noqa: F811
    """A CA-signed client with an unmapped CN must fail authorization."""
    duthost = gnmi_tls.duthost
    client_key = "GNMI_CLIENT_CERT|test.client.gnmi.sonic"
    role = duthost.shell(
        'sonic-db-cli CONFIG_DB hget "{}" "role@"'.format(client_key)
    )["stdout"].strip()
    assert role, "Managed TLS client certificate role is not configured"

    # Prove the same certificate/client works before removing its CN mapping.
    gnmi_tls.pygnmi_client.capabilities()
    try:
        duthost.shell('sonic-db-cli CONFIG_DB del "{}"'.format(client_key))
        with pytest.raises(PygnmiClientError, match="(?i)unauthenticated"):
            gnmi_tls.pygnmi_client.capabilities()
    finally:
        duthost.shell(
            'sonic-db-cli CONFIG_DB hset "{}" "role@" "{}"'.format(client_key, role)
        )
