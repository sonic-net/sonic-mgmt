import pytest
import logging

from tests.common.fixtures.grpc_fixtures import gnmi_tls  # noqa: F401
from tests.common.helpers.gnmi_utils import gnmi_capabilities
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.common.pygnmi_client import PygnmiClientError

logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def test_gnmi_authorize_passed_with_valid_cname(duthosts,
                                                rand_one_dut_hostname,
                                                localhost):
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = gnmi_capabilities(duthost, localhost)
    logger.debug("test_gnmi_authorize_passed_with_valid_cname: {}".format(msg))

    assert "Unauthenticated" not in msg, (
        "'Unauthenticated' error message found in GNMI response. "
        "- Actual message: '{}'"
    ).format(msg)


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
