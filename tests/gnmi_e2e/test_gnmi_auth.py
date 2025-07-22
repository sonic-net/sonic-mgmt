import pytest
import logging

from tests.common.helpers.gnmi_utils import gnmi_capabilities, add_gnmi_client_common_name, \
                                            del_gnmi_client_common_name
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure

logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


@pytest.fixture(scope="function")
def setup_invalid_client_cert_cname(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    del_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")
    add_gnmi_client_common_name(duthost, "invalid.cname")

    keys = duthost.shell('sudo sonic-db-cli CONFIG_DB keys GNMI*')["stdout_lines"]
    logger.debug("GNMI client cert keys: {}".format(keys))

    yield

    del_gnmi_client_common_name(duthost, "invalid.cname")
    add_gnmi_client_common_name(duthost, "test.client.gnmi.sonic")


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


def test_gnmi_authorize_failed_with_invalid_cname(duthosts,
                                                  rand_one_dut_hostname,
                                                  localhost,
                                                  setup_invalid_client_cert_cname):
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = gnmi_capabilities(duthost, localhost)
    logger.debug("test_gnmi_authorize_failed_with_invalid_cname: {}".format(msg))

    assert "Unauthenticated" in msg, (
        "'Unauthenticated' error message not found in GNMI response. "
        "- Actual message: '{}'"
    ).format(msg)
