import pytest
import logging

from .helper import gnmi_capabilities
from tests.common.fixtures.tacacs import tacacs_creds, setup_tacacs    # noqa F401

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]


def test_gnmi_capabilities(duthosts, rand_one_dut_hostname, localhost):
    '''
    Verify GNMI capabilities
    '''
    duthost = duthosts[rand_one_dut_hostname]
    ret, msg = gnmi_capabilities(duthost, localhost)
    assert ret == 0, msg
    assert "sonic-db" in msg, msg
    assert "JSON_IETF" in msg, msg
