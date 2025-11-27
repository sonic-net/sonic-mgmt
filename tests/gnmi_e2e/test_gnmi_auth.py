import pytest
import logging

from tests.common.helpers.gnmi_utils import gnmi_capabilities
from tests.common.plugins.allure_wrapper import allure_step_wrapper as allure
from tests.gnmi_e2e.helper import setup_invalid_client_cert_cname        # noqa: F401
from tests.common.fixtures.duthost_utils import duthost_mgmt_ip          # noqa: F401

logger = logging.getLogger(__name__)
allure.logger = logger

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def test_gnmi_authorize_passed_with_valid_cname(duthosts,
                                                rand_one_dut_hostname,
                                                localhost,
                                                duthost_mgmt_ip):  # noqa: F811
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = gnmi_capabilities(duthost, localhost, duthost_mgmt_ip)
    logger.debug("test_gnmi_authorize_passed_with_valid_cname: {}".format(msg))

    assert "Unauthenticated" not in msg, (
        "'Unauthenticated' error message found in GNMI response. "
        "- Actual message: '{}'"
    ).format(msg)


def test_gnmi_authorize_failed_with_invalid_cname(duthosts,
                                                  rand_one_dut_hostname,
                                                  localhost,
                                                  setup_invalid_client_cert_cname,   # noqa: F811
                                                  duthost_mgmt_ip):                  # noqa: F811
    '''
    Verify GNMI native write, incremental config for configDB
    GNMI set request with invalid path
    '''
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = gnmi_capabilities(duthost, localhost, duthost_mgmt_ip)
    logger.debug("test_gnmi_authorize_failed_with_invalid_cname: {}".format(msg))

    assert "Unauthenticated" in msg, (
        "'Unauthenticated' error message not found in GNMI response. "
        "- Actual message: '{}'"
    ).format(msg)
